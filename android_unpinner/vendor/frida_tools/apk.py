from __future__ import annotations
# vendored from https://github.com/mhils/frida-tools/blob/9285b273de68e3c95a22c713d9840bf9d21e6e8b/frida_tools/apk.py

import os
import struct
from enum import IntEnum
from io import BufferedReader
from zipfile import ZipFile


def make_debuggable(path: str, output_path: str) -> None:
    with ZipFile(path, "r") as iz, ZipFile(output_path, "w") as oz:
        for info in iz.infolist():
            with iz.open(info) as f:
                if info.filename == "AndroidManifest.xml":
                    manifest = BinaryXML(f)

                    pool = None
                    debuggable_index = None

                    size = 8
                    for header in manifest.chunk_headers[1:]:
                        if header.type == ChunkType.STRING_POOL:
                            pool = StringPool(header)
                            debuggable_index = pool.append_str("debuggable")

                        if header.type == ChunkType.RESOURCE_MAP:
                            # the "debuggable" attribute name is not only a reference to the string pool, but
                            # also to the resource map. We need to extend the resource map with a valid entry.
                            # refs https://justanapplication.wordpress.com/category/android/android-binary-xml/android-xml-startelement-chunk/
                            resource_map = ResourceMap(header)
                            resource_map.add_debuggable(debuggable_index)

                        if header.type == ChunkType.START_ELEMENT:
                            start = StartElement(header)
                            name = pool.get_string(start.name)
                            if name == "application":
                                start.insert_debuggable(debuggable_index, resource_map)

                        size += header.size

                    header = manifest.chunk_headers[0]
                    header_data = bytearray(header.chunk_data)
                    header_data[4:4 + 4] = struct.pack("<I", size)

                    data = bytearray()
                    data.extend(header_data)
                    for header in manifest.chunk_headers[1:]:
                        data.extend(header.chunk_data)

                    oz.writestr(info.filename, bytes(data), info.compress_type)
                elif info.filename.startswith("META-INF"):
                    pass
                else:
                    oz.writestr(info.filename, f.read(), info.compress_type)


class BinaryXML:
    def __init__(self, stream: BufferedReader):
        self.stream = stream
        self.chunk_headers = []
        self.parse()

    def parse(self) -> None:
        chunk_header = ChunkHeader(self.stream, False)
        if chunk_header.type != ChunkType.XML:
            raise BadHeader()
        self.chunk_headers.append(chunk_header)

        size = chunk_header.size

        while self.stream.tell() < size:
            chunk_header = ChunkHeader(self.stream)
            self.chunk_headers.append(chunk_header)


class ChunkType(IntEnum):
    STRING_POOL = 0x001
    XML = 0x003
    START_ELEMENT = 0x102
    RESOURCE_MAP = 0x180


class ResourceType(IntEnum):
    BOOL = 0x12


class StringType(IntEnum):
    UTF8 = 1 << 8


class BadHeader(Exception):
    pass


class ChunkHeader:
    FORMAT = "<HHI"

    def __init__(self, stream: BufferedReader, consume_data=True):
        self.stream = stream
        data = self.stream.peek(struct.calcsize(self.FORMAT))
        (self.type, self.header_size, self.size) = struct.unpack_from(self.FORMAT, data)
        if consume_data:
            self.chunk_data = self.stream.read(self.size)
        else:
            self.chunk_data = self.stream.read(struct.calcsize(self.FORMAT))


class StartElement:
    FORMAT = "<HHIIIIIIHHHH"
    ATTRIBUTE_FORMAT = "<IIiHBBi"

    def __init__(self, header: ChunkHeader) -> None:
        self.header = header
        self.stream = self.header.stream
        self.header_size = struct.calcsize(self.FORMAT)

        data = struct.unpack_from(self.FORMAT, self.header.chunk_data)
        if data[0] != ChunkType.START_ELEMENT:
            raise BadHeader()

        self.name = data[6]
        self.attribute_count = data[8]

        attributes_data = self.header.chunk_data[self.header_size:]
        if len(attributes_data[-20:]) == 20:
            previous_attribute = struct.unpack(
                self.ATTRIBUTE_FORMAT, attributes_data[-20:])
            self.namespace = previous_attribute[0]
        else:
            # There are no other attributes in the application tag
            self.namespace = -1

    def insert_debuggable(self, name: int, resource_map: ResourceMap) -> None:
        # TODO: Instead of using the previous attribute to determine the probable
        # namespace for the debuggable tag we could scan the strings section
        # for the AndroidManifest schema tag
        if self.namespace == -1:
            raise BadHeader()

        chunk_data = bytearray(self.header.chunk_data)

        resource_size = 8
        resource_type = ResourceType.BOOL
        # Denotes a True value in AXML, 0 is used for False
        resource_data = -1

        debuggable = struct.pack(self.ATTRIBUTE_FORMAT, self.namespace,
                                 name, -1, resource_size, 0, resource_type, resource_data)

        # some parts of Android expect this to be sorted by resource id.
        attr_offset = None
        for insert_pos in range(self.attribute_count + 1):
            attr_offset = 0x24 + 20 * insert_pos
            idx = int.from_bytes(chunk_data[attr_offset + 4:attr_offset + 8], "little")
            # print(f"{idx=} {resource_map.get_resource(idx)=:x}")
            if resource_map.get_resource(idx) > ResourceMap.DEBUGGING_RESOURCE:
                break
        # print(f"Inserting debuggable at position {insert_pos}.")
        chunk_data[attr_offset:attr_offset] = debuggable

        self.header.size = len(chunk_data)
        chunk_data[4:4 + 4] = struct.pack("<I", self.header.size)

        self.attribute_count += 1
        chunk_data[28:28 + 2] = struct.pack("<H", self.attribute_count)

        self.header.chunk_data = bytes(chunk_data)


class ResourceMap:
    DEBUGGING_RESOURCE = 0x101000f

    def __init__(self, header: ChunkHeader):
        self.header = header

    def add_debuggable(self, idx: int) -> None:
        assert idx is not None
        data_size = len(self.header.chunk_data) - 8
        target = (idx + 1) * 4
        self.header.chunk_data += (
            b"\x00" * (target - data_size - 4)
            + self.DEBUGGING_RESOURCE.to_bytes(4, "little")
        )

        # Recalculate size
        self.header.size = len(self.header.chunk_data)
        self.header.chunk_data = (
            self.header.chunk_data[:4] +
            struct.pack("<I", self.header.size) +
            self.header.chunk_data[8:]
        )

    def get_resource(self, index: int) -> int:
        offset = index * 4 + 8
        return int.from_bytes(self.header.chunk_data[offset:offset+4], "little")


class StringPool:
    FORMAT = "<HHIIIIII"

    def __init__(self, header: ChunkHeader):
        self.header = header
        self.stream = self.header.stream
        self.header_size = struct.calcsize(self.FORMAT)

        data = struct.unpack_from(self.FORMAT, self.header.chunk_data)
        if data[0] != ChunkType.STRING_POOL:
            raise BadHeader()

        self.string_count = data[3]
        self.flags = data[5]
        self.strings_offset = data[6]
        self.styles_offset = data[7]
        self.utf8 = (self.flags & StringType.UTF8) != 0
        self.dirty = False

        offsets_data = self.header.chunk_data[self.header_size:
                                              self.header_size + self.string_count * 4]
        self.offsets = list(
            map(lambda f: f[0], struct.iter_unpack("<I", offsets_data)))

    def get_string(self, index: int) -> str:
        offset = self.offsets[index]

        # HACK: We subtract 4 because we insert a string offset during append_str
        # but we do not update the original stream and thus it reads stale data.
        if self.dirty:
            offset -= 4

        position = self.stream.tell()
        self.stream.seek(self.strings_offset + 8 + offset, os.SEEK_SET)

        string = None
        if self.utf8:
            # Ignore UTF-16 length
            n = struct.unpack("<B", self.stream.read(1))[0]
            if n & 0x80:
                n = ((n & 0x7f) << 8) | struct.unpack(
                    "<B", self.stream.read(1))[0]

            # UTF-8 encoded length
            n = struct.unpack("<B", self.stream.read(1))[0]
            if n & 0x80:
                n = ((n & 0x7f) << 8) | struct.unpack(
                    "<B", self.stream.read(1))[0]

            string = self.stream.read(n).decode("utf-8")
        else:
            n = struct.unpack("<H", self.stream.read(2))[0]
            if n & 0x8000:
                n |= ((n & 0x7fff) << 16) | struct.unpack(
                    "<H", self.stream.read(2))[0]

            string = self.stream.read(n * 2).decode("utf-16le")

        self.stream.seek(position, os.SEEK_SET)
        return string

    def append_str(self, add: str) -> int:
        data_size = len(self.header.chunk_data)
        # Reserve data for our new offset
        data_size += 4

        chunk_data = bytearray(data_size)
        end = self.header_size + self.string_count * 4
        chunk_data[:end] = self.header.chunk_data[:end]
        chunk_data[end + 4:] = self.header.chunk_data[end:]

        # Add 4 since we have added a string offset
        offset = len(chunk_data) - 8 - self.strings_offset + 4

        if self.utf8:
            # UTF-16 length (ignored)
            chunk_data.extend(struct.pack("<B", len(add)))
            # UTF-8 length
            chunk_data.extend(struct.pack("<B", len(add)))

            chunk_data.extend(add.encode("utf-8"))
            # Insert a UTF-8 NUL
            chunk_data.extend([0])
        else:
            chunk_data.extend(struct.pack("<H", len(add)))
            chunk_data.extend(add.encode("utf-16le"))
            # Insert a UTF-16 NUL
            chunk_data.extend([0, 0])

        # Insert a new offset at the end of the existing offsets
        chunk_data[end:end + 4] = struct.pack("<I", offset)

        # Increase the header size since we have inserted a new offset and string
        self.header.size = len(chunk_data)
        chunk_data[4:4 + 4] = struct.pack("<I", self.header.size)

        self.string_count += 1
        chunk_data[8:8 + 4] = struct.pack("<I", self.string_count)

        # Increase strings offset since we have inserted a new offset and thus
        # shifted the offset of the strings
        self.strings_offset += 4
        chunk_data[20:20 + 4] = struct.pack("<I", self.strings_offset)

        # If there are styles, offset them as we have inserted into the strings
        # offsets
        if self.styles_offset != 0:
            self.styles_offset += 4
            chunk_data[24:24 + 4] = struct.pack("<I", self.strings_offset)

        self.header.chunk_data = bytes(chunk_data)

        self.dirty = True

        return self.string_count - 1
