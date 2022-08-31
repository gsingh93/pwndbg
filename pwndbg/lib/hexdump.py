"""
Hexdump implementation, ~= stolen from pwntools.
"""

import copy
import string


def groupby(array, count, fill=None):
    array = copy.copy(array)
    while fill and len(array) % count:
        array.append(fill)
    for i in range(0, len(array), count):
        yield array[i : i + count]


# TODO: Double check performance is still when using function calls instead of lookup tables
def hexdump(
    data,
    # TODO: Rename
    H,
    address=0,
    width=16,
    group_width=4,
    flip_group_endianess=False,
    skip=True,
    offset=0,
    # TODO: pass in and rename
    config_block_separator="|",
    config_byte_separator=" ",
):
    # if not color_scheme or not printable:
    #     load_color_scheme()
    data = list(bytearray(data))
    base = address
    last_line = None
    skipping = False
    for i, line in enumerate(groupby(data, width, -1)):
        if skip and line == last_line:
            if not skipping:
                skipping = True
                yield "..."
            continue
        else:
            skipping = False
            last_line = line

        hexline = []

        if address:
            hexline.append(H.offset("+%04x " % ((i + offset) * width)))

        hexline.append(H.address("%#08x  " % (base + (i * width))))

        for group in groupby(line, group_width):
            group_length = len(group)
            group = reversed(group) if flip_group_endianess else group
            for idx, char in enumerate(group):
                if flip_group_endianess and idx == group_length - 1:
                    hexline.append(H.highlight_group_lsb(H.colorize_hex(char)))
                else:
                    hexline.append(H.colorize_hex(char))
                hexline.append(str(config_byte_separator))
            hexline.append(" ")

        hexline.append(H.separator("%s" % config_block_separator))
        for group in groupby(line, group_width):
            for char in group:
                hexline.append(H.colorize_ascii(char))
            hexline.append(H.separator("%s" % config_block_separator))

        yield ("".join(hexline))

    # skip empty footer if we printed something
    if last_line:
        return

    hexline = []

    if address:
        hexline.append(H.offset("+%04x " % len(data)))

    hexline.append(H.address("%#08x  " % (base + len(data))))

    yield "".join(hexline)
