"""
A minimal, modern, asyncio-based Python 3 implementation of the Java Debug Wire Protocol.
The implemented functionality is just enough to execute commands and load libraries.

When working with JDWP, make sure to enable debug logging:

```python
logging.getLogger("jdwplib").setLevel("DEBUG")
```

References:
- <https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-spec.html>
- <https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-protocol.html>
"""
from __future__ import annotations

import asyncio
import enum
import io
import logging
import struct
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("jdwplib")

REPLY_PACKET = 0x80
HANDSHAKE = b"JDWP-Handshake"


class JDWPClient:
    """
    A Java Debug Wire Protocol Client. Usage example:

    ```python
    import asyncio

    async def run():
        async with jdwplib.JDWPClient("127.0.0.1", 1234) as client:
            thread_id = await client.advance_to_breakpoint("Landroid/app/Activity;", "onCreate")
            response = await client.exec(thread_id, "sleep 5")

    asyncio.run(run())
    ```
    ADB shortcut:
    ```python
    async with await jdwplib.JDWPClient.connect_adb() as client:
        ...
    ```
    """

    sizes: IDSizes

    def __init__(
        self,
        host: str,
        port: int,
    ):
        self.host: str = host
        self.port: int = port
        self._reply_waiter: dict[int, asyncio.Event] = {}
        self._replies: dict[int, Packet] = {}
        self.current_id: int = 0
        self.server_commands: asyncio.Queue[Packet] = asyncio.Queue()
        self._classes_cache = {}
        self._methods_cache = {}

    @classmethod
    async def connect_adb(cls, adb_binary: Path | None = None) -> JDWPClient:
        """Take the first (!) debuggable PID found via ADB, forward it via TCP, and connect to it."""
        log.info("Obtaining jdwp pid from adb...")
        if adb_binary is None:
            adb_binary = "adb"

        async def try_read_pid() -> int:
            proc = await asyncio.create_subprocess_shell(
                f"{adb_binary} jdwp",
                stdout=asyncio.subprocess.PIPE,
            )
            try:
                pid = int(await proc.stdout.readline())
            finally:
                proc.kill()
                proc._transport.close()  # https://bugs.python.org/issue43884
            return pid

        pid = None
        for i in range(1, 4):
            try:
                pid = await asyncio.wait_for(try_read_pid(), i)
                break
            except asyncio.TimeoutError:
                log.info("Timeout...")
        if pid is None:
            raise RuntimeError("`adb jdwp` did not return a process id.")
        log.info(f"{pid=}")

        log.info("Forwarding to local port...")
        proc = await asyncio.create_subprocess_shell(
            f"{adb_binary} forward tcp:0 jdwp:{pid}",
            stdout=asyncio.subprocess.PIPE,
        )
        local_port = int(await proc.stdout.readline())
        await proc.wait()
        log.info(f"{local_port=}")
        return JDWPClient("127.0.0.1", local_port)

    async def __aenter__(self) -> JDWPClient:
        log.info("Establishing connection...")
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

        log.info("Starting handshake...")
        self.writer.write(HANDSHAKE)
        reply = await self.reader.readexactly(len(HANDSHAKE))
        if reply != HANDSHAKE:
            raise RuntimeError(f"Handshake failed: {reply=}")
        self._reader_task_instance = asyncio.create_task(self._reader_task())

        log.info("Obtaining Java id sizes...")
        sizes = await self.send_command(Commands.GET_ID_SIZES)
        assert not sizes.message
        self.sizes = IDSizes(sizes.data)

        log.info("Getting version info...")
        version_info = await self.send_command(Commands.VERSION)
        buf = io.BytesIO(version_info.data)
        description = _read_str(buf)
        versions_ = buf.read(8)
        vm_version_ = _read_str(buf)
        vm_name_ = _read_str(buf)
        log.info(f"JDWP Version: {description}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.writer.close()
        self._reader_task_instance.cancel("connection closed")

    async def _reader_task(self):
        while True:
            header = await self.reader.readexactly(11)
            length, id, flags, message = struct.unpack_from("!IIBH", header)
            data = await self.reader.readexactly(length - 11)
            packet = Packet(id, flags, message, data)

            if packet.is_reply:
                self._replies[packet.id] = packet
                self._reply_waiter[packet.id].set()
            else:
                await self.server_commands.put(packet)

            log.debug(f"<< {packet}")
            if packet.is_reply and packet.message:
                log.error(f"Command errored: {packet}")

    async def send_command(self, command: Commands, data: bytes = b"") -> Packet:
        """
        Send a generic request to the VM, wait for the response, and return it.
        """
        command = Packet(self.current_id, 0, command.value, data)
        log.debug(f">> {command}")
        self.writer.write(bytes(command))
        self._reply_waiter[command.id] = asyncio.Event()
        self.current_id += 1

        await self._reply_waiter[command.id].wait()
        del self._reply_waiter[command.id]
        return self._replies.pop(command.id)

    async def get_first_class_id(self, cls_sig: str) -> bytes | None:
        """
        Get the class id for the first class matching the signature,
        e.g. "Ljava/lang/Runtime;".
        """
        if cls_sig not in self._classes_cache:
            resp = await self.send_command(
                Commands.CLASSES_BY_SIGNATURE, _encode_jdwp_str(cls_sig)
            )
            (classes,) = struct.unpack_from("!I", resp.data)
            if not classes:
                raise ValueError(f"Class not found: {cls_sig}")
            else:
                self._classes_cache[cls_sig] = resp.data[5 : 5 + self.sizes.reference]

        return self._classes_cache[cls_sig]

    async def get_first_method_id(
        self,
        cls_id: bytes,
        method_sig: str,
    ) -> bytes:
        """
        Get the method id for the first method matching the signature in the given class,
        e.g. "getRuntime". If multiple implementation are available, you can additionally specify the signature,
        e.g. "getRuntime()Ljava/lang/Runtime;".
        """
        i = method_sig.find("(")
        if i != -1:
            name = method_sig[:i]
            signature = method_sig[i:]
        else:
            name = method_sig
            signature = None

        if cls_id not in self._methods_cache:
            resp = await self.send_command(Commands.METHODS, cls_id)
            self._methods_cache[cls_id] = resp.data

        buf = io.BytesIO(self._methods_cache[cls_id])
        (methods,) = struct.unpack("!I", buf.read(4))
        for _ in range(methods):
            id = buf.read(self.sizes.method)
            n = _read_str(buf)
            sig = _read_str(buf)
            (mod_bits,) = struct.unpack("!I", buf.read(4))
            is_a_match = name == n and (signature is None or signature == sig)
            if is_a_match:
                return id

        raise ValueError(f"Method not found: {method_sig}")

    async def advance_to_breakpoint(self, cls_sig: str, method_name: str) -> bytes:
        """
        Set a breakpoint at a given location, and then resume the VM until the breakpoint is hit.
        This dance yields a correct thread id.
        """
        cls_id = await self.get_first_class_id(cls_sig)
        meth_id = await self.get_first_method_id(cls_id, method_name)

        # set breakpoint
        resp = await self.send_command(
            Commands.SET_BREAKPOINT,
            b"\x02"  # EventKind: Breakpoint
            b"\x02"  # SuspendPolicy: all
            b"\x00\x00\x00\x01"  # one modifier
            b"\x07"  # location only
            b"\x01" + cls_id + meth_id + b"\x00" * 8,
        )

        # resume vm
        await self.send_command(Commands.RESUME_VM)

        # wait for breakpoint event
        while True:
            command = await self.server_commands.get()
            if command.message == Commands.EVENT_COMPOSITE.value:
                buf = io.BytesIO(command.data)
                suspend_policy_ = buf.read(1)
                events = buf.read(4)
                kind = buf.read(1)
                request_id = buf.read(4)
                if (
                    events == b"\x00\x00\x00\x01"
                    and kind == b"\x02"
                    and request_id == resp.data
                ):
                    thread_id = buf.read(self.sizes.object)
                    break
            log.debug(f"Command did not match expected event and got discarded.")

        return thread_id

    async def get_runtime(self, thread_id: bytes) -> bytes:
        """
        Get the instance id of the current runtime.
        """
        runtime_class_id = await self.get_first_class_id("Ljava/lang/Runtime;")
        assert runtime_class_id
        get_runtime = await self.get_first_method_id(
            runtime_class_id, "getRuntime()Ljava/lang/Runtime;"
        )
        assert get_runtime

        resp = await self.send_command(
            Commands.INVOKE_STATIC_METHOD,
            runtime_class_id
            + thread_id
            + get_runtime
            + b"\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00",
        )
        runtime_id = resp.data[1 : 1 + self.sizes.object]
        return runtime_id

    async def create_string(self, s: str) -> bytes:
        """
        Create a string on the VM, get the string id in return.
        """
        resp = await self.send_command(Commands.CREATE_STRING, _encode_jdwp_str(s))
        assert resp.data
        return resp.data

    async def invoke_method(
        self,
        object_id: bytes,
        thread_id: bytes,
        class_sig: str,
        method_sig: str,
        arguments: bytes = b"\x00\x00\x00\x00",
    ) -> bytes:
        class_id = await self.get_first_class_id(class_sig)
        assert class_id
        method_id = await self.get_first_method_id(class_id, method_sig)
        assert method_id

        resp = await self.send_command(
            Commands.INVOKE_METHOD,
            object_id
            + thread_id
            + class_id
            + method_id
            + arguments
            + b"\x00\x00\x00\x00",
        )
        assert resp.message == 0

        exception = resp.data[-self.sizes.object :]
        if exception != b"\x00\x00\x00\x00\x00\x00\x00\x00":
            throwable = await self.get_first_class_id("Ljava/lang/Throwable;")
            assert throwable
            get_message = await self.get_first_method_id(
                throwable, "toString()Ljava/lang/String;"
            )
            assert get_message
            resp = await self.send_command(
                Commands.INVOKE_METHOD,
                exception
                + thread_id
                + throwable
                + get_message
                + b"\x00\x00\x00\x00"
                + b"\x00\x00\x00\x00",
            )
            assert resp.message == 0
            assert (
                resp.data[-self.sizes.object :] == b"\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            resp = await self.send_command(
                Commands.STRING_VALUE, resp.data[1 : self.sizes.reference + 1]
            )
            val = _read_str(io.BytesIO(resp.data))
            raise RuntimeError(
                f"Method invocation of {class_sig}.{method_sig} failed: {val}"
            )

        return resp.data[: -(self.sizes.object + 1)]

    async def exec(self, thread_id: bytes, cmd: str) -> int:
        """
        Execute a command using `Runtime.getRuntime().exec(cmd)`.
        """
        runtime = await self.get_runtime(thread_id)
        cmd_str = await self.create_string(cmd)

        resp = await self.invoke_method(
            runtime,
            thread_id,
            "Ljava/lang/Runtime;",
            "exec(Ljava/lang/String;)Ljava/lang/Process;",
            b"\x00\x00\x00\x01L" + cmd_str,
        )
        process = resp[1:]

        # wait for process to exit
        resp = await self.invoke_method(
            process, thread_id, "Ljava/lang/Process;", "waitFor()I"
        )
        (exit_code,) = struct.unpack_from("!I", resp, 1)

        if exit_code:
            logging.error(f"Command {cmd!r} return exit code {exit_code}")
        return exit_code

    async def load(self, thread_id: bytes, path: str):
        """
        Load a library using `Runtime.getRuntime().load(cmd)`.
        """
        runtime_id = await self.get_runtime(thread_id)
        assert runtime_id

        cmd_str = await self.create_string(path)
        args = b"\x00\x00\x00\x01L" + cmd_str
        resp = await self.invoke_method(
            runtime_id,
            thread_id,
            "Ljava/lang/Runtime;",
            "load(Ljava/lang/String;)V",
            args,
        )
        assert resp == b"V"


@dataclass
class Packet:
    """
    A packet sent over the connection, can be either a command or a reply.

    <https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-spec.html#jdwp-packets>
    """

    id: int
    flags: int
    message: int
    """
    Bytes 10-11 of the packet as a big-endian integer.
    For commands, this is the command set and the command id.
    For replies, this is the error code.
    """
    data: bytes

    @property
    def is_reply(self) -> bool:
        return bool(self.flags & REPLY_PACKET)

    def __repr__(self):
        if self.is_reply:
            typ = "Reply"
            message = f"0x{self.message:04x}"
        else:
            typ = "Commd"
            try:
                message = Commands(self.message).name
            except ValueError:
                message = f"0x{self.message:04x}"
        return f"{typ}(0x{self.id:04x}, {message}, {self.data!r})"

    def __bytes__(self):
        total_len = 11 + len(self.data)
        return (
            struct.pack("!IIBH", total_len, self.id, self.flags, self.message)
            + self.data
        )


@dataclass
class IDSizes:
    """
    Container type holding the size information of various data type on the VM.

    <https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_IDSizes>
    """

    field: int
    method: int
    object: int
    reference: int
    frame: int

    def __init__(self, data: bytes):
        (
            self.field,
            self.method,
            self.object,
            self.reference,
            self.frame,
        ) = struct.unpack("!IIIII", data)


class Commands(enum.IntEnum):
    """
    Incomplete enumeration of command constants taken from
    <https://docs.oracle.com/en/java/javase/17/docs/specs/jdwp/jdwp-protocol.html>.

    For example, the IDSizes command is command set 1 and command 7. We represent it as
    `0x0107`.
    """

    VERSION = 0x0101
    CLASSES_BY_SIGNATURE = 0x0102
    GET_ID_SIZES = 0x0107
    RESUME_VM = 0x0109
    CREATE_STRING = 0x010B
    METHODS = 0x0205
    INVOKE_STATIC_METHOD = 0x0303
    INVOKE_METHOD = 0x0906
    SET_BREAKPOINT = 0x0F01
    EVENT_COMPOSITE = 0x4064
    STRING_VALUE = 0x0A01


def _read_str(buf: io.BytesIO) -> str:
    """Read a length-prefixed UTF8 string from a buffer."""
    (l,) = struct.unpack("!I", buf.read(4))
    return buf.read(l).decode()


def _encode_jdwp_str(x: str) -> bytes:
    """Encode a string as length-prefixed UTF8."""
    x = x.encode()
    return len(x).to_bytes(4, "big") + x
