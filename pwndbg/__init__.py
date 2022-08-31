import sys

import signal

import pwndbg.arguments
import pwndbg.argv
import pwndbg.color
import pwndbg.commands
import pwndbg.commands.argv
import pwndbg.commands.aslr
import pwndbg.commands.attachp
import pwndbg.commands.auxv
import pwndbg.commands.canary
import pwndbg.commands.checksec
import pwndbg.commands.comments
import pwndbg.commands.config
import pwndbg.commands.context
import pwndbg.commands.cpsr
import pwndbg.commands.dt
import pwndbg.commands.dumpargs
import pwndbg.commands.elf
import pwndbg.commands.flags
import pwndbg.commands.gdbinit
import pwndbg.commands.ghidra
import pwndbg.commands.got
import pwndbg.commands.heap
import pwndbg.commands.hexdump
import pwndbg.commands.ida
import pwndbg.commands.leakfind
import pwndbg.commands.memoize
import pwndbg.commands.misc
import pwndbg.commands.mprotect
import pwndbg.commands.next
import pwndbg.commands.p2p
import pwndbg.commands.peda
import pwndbg.commands.pie
import pwndbg.commands.probeleak
import pwndbg.commands.procinfo
import pwndbg.commands.radare2
import pwndbg.commands.reload
import pwndbg.commands.rop
import pwndbg.commands.ropper
import pwndbg.commands.search
import pwndbg.commands.segments
import pwndbg.commands.shell
import pwndbg.commands.stack
import pwndbg.commands.start
import pwndbg.commands.telescope
import pwndbg.commands.theme
import pwndbg.commands.version
import pwndbg.commands.vmmap
import pwndbg.commands.windbg
import pwndbg.commands.xinfo
import pwndbg.commands.xor
import pwndbg.constants
import pwndbg.disasm
import pwndbg.disasm.arm
import pwndbg.disasm.jump
import pwndbg.disasm.mips
import pwndbg.disasm.ppc
import pwndbg.disasm.sparc
import pwndbg.disasm.x86
import pwndbg.exception
import pwndbg.gdb
import pwndbg.gdb.abi
import pwndbg.gdb.android
import pwndbg.gdb.arch
import pwndbg.gdb.ctypes
import pwndbg.gdb.elf
import pwndbg.gdb.events
import pwndbg.gdb.glibc
import pwndbg.gdb.hooks
import pwndbg.gdb.memory
import pwndbg.gdb.next
import pwndbg.gdb.proc
import pwndbg.gdb.prompt
import pwndbg.gdb.qemu
import pwndbg.gdb.regs
import pwndbg.gdb.stack
import pwndbg.gdb.strings
import pwndbg.gdb.symbol
import pwndbg.gdb.typeinfo
import pwndbg.gdb.vmmap
import pwndbg.gdbutils.functions
import pwndbg.heap
import pwndbg.net
import pwndbg.ui
import pwndbg.wrappers
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.lib.version import __version__

version = __version__

try:
    import unicorn

    import pwndbg.emu
except Exception:
    pass

__all__ = [
    "arch",
    "auxv",
    "chain",
    "color",
    "disasm",
    "dt",
    "elf",
    "enhance",
    "events",
    "file",
    "function",
    "heap",
    "hexdump",
    "ida",
    "info",
    "leakfind",
    "linkmap",
    "malloc",
    "memoize",
    "memory",
    "p2p",
    "proc",
    "regs",
    "remote",
    "search",
    "stack",
    "strings",
    "symbol",
    "typeinfo",
    "ui",
    "vmmap",
]

pwndbg.gdb.prompt.set_prompt()

pre_commands = """
set confirm off
set verbose off
set pagination off
set height 0
set history expansion on
set history save on
set follow-fork-mode child
set backtrace past-main on
set step-mode on
set print pretty on
set width %i
handle SIGALRM nostop print nopass
handle SIGBUS  stop   print nopass
handle SIGPIPE nostop print nopass
handle SIGSEGV stop   print nopass
""".strip() % (
    pwndbg.ui.get_window_size()[1]
)

# TODO, if we import this, it takes the place of pwndbg.gdb
import gdb as gdb_

for line in pre_commands.strip().splitlines():
    gdb_.execute(line)

# This may throw an exception, see pwndbg/pwndbg#27
try:
    gdb_.execute("set disassembly-flavor intel")
except gdb_.error:
    pass

# handle resize event to align width and completion
signal.signal(
    signal.SIGWINCH,
    lambda signum, frame: gdb_.execute("set width %i" % pwndbg.ui.get_window_size()[1]),
)

# Workaround for gdb bug described in #321 ( https://github.com/pwndbg/pwndbg/issues/321 )
# More info: https://sourceware.org/bugzilla/show_bug.cgi?id=21946
# As stated on GDB's bugzilla that makes remote target search slower.
# After GDB gets the fix, we should disable this only for bugged GDB versions.
if 1:
    gdb_.execute("set remote search-memory-packet off")

# Reading Comment file
pwndbg.commands.comments.init()
