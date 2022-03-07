from __future__ import annotations

import asyncio
import enum
import io
import logging
import struct
from dataclasses import dataclass


log = logging.getLogger('jdwplib')


REPLY_PACKET = 0x80
HANDSHAKE = b"JDWP-Handshake"


@dataclass
class Packet:
    id: int
    flags: int
    message: int
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
        return struct.pack("!IIBH", total_len, self.id, self.flags, self.message) + self.data


@dataclass
class IDSizes:
    field: int
    method: int
    object: int
    reference: int
    frame: int

    def __init__(self, data: bytes):
        self.field, self.method, self.object, self.reference, self.frame = struct.unpack("!IIIII", data)


class Commands(enum.IntEnum):
    VERSION = 0x0101
    CLASSES_BY_SIGNATURE = 0x0102
    GET_ID_SIZES = 0x0107
    RESUME_VM = 0x0109
    CREATE_STRING = 0x010b
    METHODS = 0x0205
    INVOKE_STATIC_METHOD = 0x0303
    INVOKE_METHOD = 0x0906
    SET_BREAKPOINT = 0x0f01
    EVENT_COMPOSITE = 0x4064


class JDWPClient:
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

    @classmethod
    async def connect_adb(cls) -> JDWPClient:
        log.info("Obtaining jdwp pid from adb...")

        async def try_read_pid() -> int:
            proc = await asyncio.create_subprocess_shell(
                "adb jdwp",
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
            f"adb forward tcp:0 jdwp:{pid}",
            stdout=asyncio.subprocess.PIPE,
        )
        local_port = int(await proc.stdout.readline())
        await proc.wait()
        log.info(f"{local_port=}")
        return JDWPClient("127.0.0.1", local_port)

    async def __aenter__(self) -> JDWPClient:
        log.info("Establishing connection...")
        self.reader, self.writer = await asyncio.open_connection(
            self.host,
            self.port
        )

        log.info("Connection established. Starting handshake...")
        self.writer.write(HANDSHAKE)
        reply = await self.reader.readexactly(len(HANDSHAKE))
        if reply != HANDSHAKE:
            raise RuntimeError(f"Handshake failed: {reply=}")
        self._reader_task = asyncio.create_task(self.reader_task())

        log.info("Handshake completed. Obtaining id sizes...")
        sizes = await self.send_command(Commands.GET_ID_SIZES)
        assert not sizes.message
        self.sizes = IDSizes(sizes.data)

        log.info("ID sizes obtained.")
        # await self.send_command(Commands.VERSION)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.writer.close()
        self._reader_task.cancel("connection closed")

    async def reader_task(self):
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
        command = Packet(self.current_id, 0, command.value, data)
        log.debug(f">> {command}")
        self.writer.write(bytes(command))
        self._reply_waiter[command.id] = asyncio.Event()
        self.current_id += 1

        await self._reply_waiter[command.id].wait()
        del self._reply_waiter[command.id]
        return self._replies.pop(command.id)

    async def get_first_class_ref(self, cls_sig: str) -> bytes | None:
        resp = await self.send_command(
            Commands.CLASSES_BY_SIGNATURE,
            _encode_jdwp_str(cls_sig)
        )
        classes, = struct.unpack_from("!I", resp.data)
        if not classes:
            return None
        else:
            return resp.data[5:5 + self.sizes.reference]

    async def get_first_method_ref(self, cls_ref: bytes, method_name: str) -> bytes | None:
        resp = await self.send_command(Commands.METHODS, cls_ref)
        buf = io.BytesIO(resp.data)
        methods, = struct.unpack("!I", buf.read(4))
        for _ in range(methods):
            id = buf.read(self.sizes.method)
            name = _read_str(buf)
            signature_ = _read_str(buf)
            mod_bits_ = buf.read(4)

            if method_name == name:
                return id
        return None

    async def advance_to_breakpoint(self, cls_sig: str, method_name: str) -> bytes:
        cls_ref = await self.get_first_class_ref(cls_sig)
        meth_ref = await self.get_first_method_ref(cls_ref, method_name)

        # set breakpoint
        resp = await self.send_command(
            Commands.SET_BREAKPOINT,
            b"\x02"  # EventKind: Breakpoint
            b"\x02"  # SuspendPolicy: all
            b"\x00\x00\x00\x01"  # one modifier
            b"\x07"  # location only
            b"\x01" + cls_ref + meth_ref + b"\x00" * 8
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
                if events == b"\x00\x00\x00\x01" and kind == b"\x02" and request_id == resp.data:
                    thread_id = buf.read(self.sizes.object)
                    break
            log.debug(f"Command did not match and got discarded.")

        return thread_id

    async def get_runtime(self, thread_id: bytes, runtime_class_id: bytes) -> bytes:
        get_runtime = await self.get_first_method_ref(runtime_class_id, "getRuntime")
        assert get_runtime

        resp = await self.send_command(
            Commands.INVOKE_STATIC_METHOD,
            runtime_class_id +
            thread_id +
            get_runtime +
            b"\x00\x00\x00\x00" +
            b"\x00\x00\x00\x00"
        )
        runtime_id = resp.data[1:1 + self.sizes.object]
        return runtime_id

    async def create_string(self, s: str) -> bytes:
        resp = await self.send_command(Commands.CREATE_STRING, _encode_jdwp_str(s))
        assert resp.data
        return resp.data

    async def exec(self, thread_id: bytes, cmd: str):
        runtime_class_id = await self.get_first_class_ref("Ljava/lang/Runtime;")
        assert runtime_class_id
        runtime = await self.get_runtime(thread_id, runtime_class_id)
        assert runtime

        exec = await self.get_first_method_ref(runtime_class_id, "exec")
        assert exec

        cmd_str = await self.create_string(cmd)
        resp = await self.send_command(
            Commands.INVOKE_METHOD,
            runtime +
            thread_id +
            runtime_class_id +
            exec +
            b"\x00\x00\x00\x01" +
            b"L" + cmd_str +
            b"\x00\x00\x00\x00"
        )
        assert resp.message == 0
        assert resp.data[self.sizes.object + 1:] == b"L" + b"\x00" * self.sizes.object
        process = resp.data[1:self.sizes.object + 1]

        # wait for process to exit
        process_class_id = await self.get_first_class_ref("Ljava/lang/Process;")
        assert process_class_id
        wait_for = await self.get_first_method_ref(process_class_id, "waitFor")
        assert wait_for

        resp = await self.send_command(
            Commands.INVOKE_METHOD,
            process +
            thread_id +
            process_class_id +
            wait_for +
            b"\x00\x00\x00\x00" +
            b"\x00\x00\x00\x00"
        )
        assert resp.message == 0
        assert resp.data == b'I\x00\x00\x00\x00L\x00\x00\x00\x00\x00\x00\x00\x00'

    async def load(self, thread_id: bytes, path: str):
        class_id = await self.get_first_class_ref("Ljava/lang/Runtime;")
        assert class_id
        runtime_id = await self.get_runtime(thread_id, class_id)
        assert runtime_id

        load = await self.get_first_method_ref(class_id, "load")
        assert load

        cmd_str = await self.create_string(path)
        resp = await self.send_command(
            Commands.INVOKE_METHOD,
            runtime_id +
            thread_id +
            class_id +
            load +
            b"\x00\x00\x00\x01" +
            b"L" + cmd_str +
            b"\x00\x00\x00\x00"
        )
        try:
            assert resp.message == 0
            assert resp.data == b"VL" + b"\x00" * self.sizes.object
        except AssertionError:
            log.error(f"Failed to load library: {resp}")
            raise


def _read_str(buf: io.BytesIO) -> str:
    l, = struct.unpack("!I", buf.read(4))
    return buf.read(l).decode()


def _encode_jdwp_str(x: str) -> bytes:
    x = x.encode()
    return len(x).to_bytes(4, "big") + x


async def main():
    PKG_NAME = "tech.httptoolkit.pinning_demo"
    LIBGADGET = "libgadget.so"
    LIBGADGET_CONF = "libgadget.config.so"

    await (await asyncio.create_subprocess_shell(
        f"adb shell am force-stop {PKG_NAME}"
    )).wait()
    await (await asyncio.create_subprocess_shell(
        f"adb shell am set-debug-app -w {PKG_NAME}"
    )).wait()
    await (await asyncio.create_subprocess_shell(
        f"adb shell monkey -p {PKG_NAME} 1"
    )).wait()

    async with await JDWPClient.connect_adb() as client:

        thread_id = await client.advance_to_breakpoint("Landroid/app/Activity;", "onCreate")
        await client.exec(thread_id, f"cp /data/local/tmp/{LIBGADGET} /data/data/{PKG_NAME}/{LIBGADGET}")
        await client.exec(thread_id, f"cp /data/local/tmp/{LIBGADGET_CONF} /data/data/{PKG_NAME}/{LIBGADGET_CONF}")
        await client.load(thread_id, f"/data/data/{PKG_NAME}/{LIBGADGET}")
        await client.send_command(Commands.RESUME_VM)


    await asyncio.sleep(2)
    await (await asyncio.create_subprocess_shell(
        f"adb shell monkey -p {PKG_NAME} --pct-touch 100 --throttle 10 500"
    )).wait()


if __name__ == "__main__":
    asyncio.run(main())
