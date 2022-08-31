import gdb

import pwndbg.gdb.proc
from pwndbg.gdb import typeinfo
from pwndbg.lib.arch import Arch

# from capstone import *


# TODO: x86-64 needs to come before i386 in the current implementation, make
# this order-independent
ARCHS = ("x86-64", "i386", "aarch64", "mips", "powerpc", "sparc", "arm")

arch = Arch("i386", typeinfo.ptrsize, "little")


def _get_arch(ptrsize):
    not_exactly_arch = False

    if "little" in gdb.execute("show endian", to_string=True).lower():
        endian = "little"
    else:
        endian = "big"

    if pwndbg.gdb.proc.alive:
        arch = gdb.newest_frame().architecture().name()
    else:
        arch = gdb.execute("show architecture", to_string=True).strip()
        not_exactly_arch = True

    # Below, we fix the fetched architecture
    for match in ARCHS:
        if match in arch:
            return match, ptrsize, endian

    # TODO: Fix arm and armcm

    if not_exactly_arch:
        raise RuntimeError("Could not deduce architecture from: %s" % arch)

    return arch, ptrsize, endian


def update():
    # TODO: By overwriting this variable, modules that have already imported it
    # will not get the update. I could have a global context variable that it's
    # stored in that never gets overwritten, or I can call __init__ again
    arch_name, ptrsize, endian = _get_arch(typeinfo.ptrsize)
    arch.__init__(arch_name, ptrsize, endian)
