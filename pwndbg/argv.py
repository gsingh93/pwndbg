import gdb

import pwndbg.gdb.abi
import pwndbg.gdb.arch
import pwndbg.gdb.events
import pwndbg.gdb.hooks
import pwndbg.gdb.memory
import pwndbg.gdb.regs

#: Total number of arguments
argc = None

#: Pointer to argv on the stack
argv = None

#: Pointer to envp on the stack
envp = None

#: Total number of environment variables
envc = None


@pwndbg.gdb.events.start
@pwndbg.gdb.abi.LinuxOnly()
def update():
    global argc
    global argv
    global envp
    global envc

    pwndbg.gdb.hooks.update_arch()  # :-(

    sp = pwndbg.gdb.regs.sp
    ptrsize = pwndbg.gdb.arch.ptrsize
    ptrbits = 8 * ptrsize

    try:
        argc = pwndbg.gdb.memory.u(sp, ptrbits)
    except Exception:
        return

    sp += ptrsize

    argv = sp

    while pwndbg.gdb.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize

    envp = sp

    envc = 0
    try:
        while pwndbg.gdb.memory.u(sp, ptrbits):
            sp += ptrsize
            envc += 1
    except gdb.MemoryError:
        pass
