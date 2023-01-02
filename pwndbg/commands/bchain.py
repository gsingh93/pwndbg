import argparse

import gdb

import pwndbg.commands

parser = argparse.ArgumentParser()
parser.description = ""
parser.add_argument("locations", nargs="+", type=str)


# TODO: need to use this workaround: https://github.com/pwndbg/pwndbg/issues/425
@pwndbg.commands.ArgparsedCommand(parser, aliases=["breakchain"])
def bchain(locations):
    bp_command = ""
    for loc in reversed(locations[1:]):
        if bp_command != "":
            bp_command = f"""
                tbreak {loc}
                commands
                    {bp_command}
                    continue
                end
            """
        else:
            bp_command = f"tbreak {loc}"

    if bp_command == "":
        bp_command = f"break {locations[0]}"
    else:
        bp_command = f"""
        break {locations[0]}
        commands
            {bp_command}
            continue
        end
        """

    print(bp_command)
    gdb.execute(bp_command)
