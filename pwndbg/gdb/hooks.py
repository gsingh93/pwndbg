import pwndbg.gdb.events
import pwndbg.gdb.typeinfo
from pwndbg.gdb import arch_
from pwndbg.lib.memoize import forever
from pwndbg.lib.memoize import reset_on_cont
from pwndbg.lib.memoize import reset_on_exit
from pwndbg.lib.memoize import reset_on_objfile
from pwndbg.lib.memoize import reset_on_prompt
from pwndbg.lib.memoize import reset_on_start
from pwndbg.lib.memoize import reset_on_stop
from pwndbg.lib.memoize import while_running


@pwndbg.gdb.events.new_objfile
@pwndbg.gdb.events.start
@pwndbg.gdb.events.stop
def update_typeinfo():
    pwndbg.gdb.typeinfo.update()


@pwndbg.gdb.events.start
@pwndbg.gdb.events.stop
@pwndbg.gdb.events.new_objfile
def update_arch():
    arch_.update()


def init():
    update_arch()
    update_typeinfo()


@pwndbg.gdb.events.stop
@pwndbg.gdb.events.mem_changed
@pwndbg.gdb.events.reg_changed
def memoize_on_stop():
    reset_on_stop._reset()


@pwndbg.gdb.events.before_prompt
def memoize_before_prompt():
    reset_on_prompt._reset()


@pwndbg.gdb.events.cont
def memoize_on_cont():
    reset_on_cont._reset()


@pwndbg.gdb.events.new_objfile
def memoize_on_new_objfile():
    reset_on_objfile._reset()


@pwndbg.gdb.events.start
def memoize_on_start():
    while_running._start_caching()
    reset_on_start._reset()


@pwndbg.gdb.events.exit
def memoize_on_exit():
    while_running._reset()
    reset_on_exit._reset()


init()
