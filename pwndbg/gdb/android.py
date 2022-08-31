import gdb

import pwndbg.color.message as message
import pwndbg.file
import pwndbg.gdb.events
import pwndbg.gdb.qemu
import pwndbg.gdb.remote
import pwndbg.lib.memoize


@pwndbg.lib.memoize.reset_on_start
@pwndbg.lib.memoize.reset_on_exit
def is_android():
    if pwndbg.gdb.qemu.is_qemu():
        return False

    try:
        if pwndbg.file.get("/system/etc/hosts"):
            return True
    except OSError:
        pass

    return False


@pwndbg.gdb.events.start
def sysroot():
    cmd = "set sysroot remote:/"
    if is_android():
        if gdb.parameter("sysroot") == "target:":
            gdb.execute(cmd)
        else:
            print(message.notice("sysroot is already set, skipping %r" % cmd))
