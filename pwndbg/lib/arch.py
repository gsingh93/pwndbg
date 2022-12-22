import struct
import sys

from enum import Enum


class Architecture(str, Enum):
    X86_64 = "x86-64"
    I386 = "i386"
    AARCH64 = "aarch64"
    MIPS = "mips"
    POWERPC = "powerpc"
    SPARC = "sparc"
    ARM = "arm"
    ARMCM = "armcm"

class Endianness(str, Enum):
    LITTLE = "little"
    BIG = "big"

class Arch:
    def __init__(self, arch_name: str, ptrsize: int, endian: str) -> None:
        self.name = arch_name
        # TODO: `current` is the old name for the arch name, and it's now an
        # alias for `name`. It's used throughout the codebase, do we want to
        # migrate these uses to `name`?
        self.current = self.name
        self.ptrsize = ptrsize
        self.ptrmask = (1 << 8 * ptrsize) - 1
        self.endian = endian

        self.fmt = {(4, "little"): "<I", (4, "big"): ">I", (8, "little"): "<Q", (8, "big"): ">Q"}[
            (self.ptrsize, self.endian)
        ]  # type: str

        if self.name == Architecture.ARM and self.endian == Endianness.BIG:
            self.qemu = "armeb"
        elif self.name == Architecture.MIPS and self.endian == Endianness.LITTLE:
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

        self.native_endian = str(sys.byteorder)

    def pack(self, integer: int) -> bytes:
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data: bytes) -> int:
        return struct.unpack(self.fmt, data)[0]

    def signed(self, integer: int) -> int:
        return self.unpack(self.pack(integer), signed=True)  # type: ignore

    def unsigned(self, integer: int) -> int:
        return self.unpack(self.pack(integer))
