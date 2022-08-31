import struct
import sys


class Arch:
    def __init__(self, arch_name, ptrsize, endian):
        # Distinguish between Cortex-M and other ARM
        # if 'arm' in arch_name and '-m'
        #     arch_name = 'armcm' if '-m' in arch_name else 'arm'

        self.name = arch_name
        # Alias for old global variable name
        self.current = self.name
        self.ptrsize = ptrsize
        self.ptrmask = (1 << 8 * ptrsize) - 1
        self.endian = endian

        self.fmt = {
            (4, "little"): "<I",
            (4, "big"): ">I",
            (8, "little"): "<Q",
            (8, "big"): ">Q",
        }.get((self.ptrsize, self.endian))

        if self.name == "arm" and self.endian == "big":
            self.qemu = "armeb"
        elif self.name == "mips" and self.name == "little":
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

        self.native_endian = str(sys.byteorder)

    def pack(self, integer):
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data):
        return struct.unpack(self.fmt, data)[0]

    def signed(self, integer):
        return self.unpack(self.pack(integer), signed=True)

    def unsigned(integer):
        return self.unpack(self.pack(integer))
