import pwndbg.chain
import pwndbg.commands
import pwndbg.gdb.auxv


@pwndbg.commands.ArgparsedCommand("Print information from the Auxiliary ELF Vector.")
@pwndbg.commands.OnlyWhenRunning
def auxv():
    for k, v in pwndbg.gdb.auxv.get().items():
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, int) else pwndbg.chain.format(v))
