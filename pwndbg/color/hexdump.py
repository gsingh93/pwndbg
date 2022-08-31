import string

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

printable_chars = set(string.printable) - set(string.whitespace)

config_normal = theme.ColoredParameter(
    "hexdump-normal-color", "none", "color for hexdump command (normal bytes)"
)
config_printable = theme.ColoredParameter(
    "hexdump-printable-color", "bold", "color for hexdump command (printable characters)"
)
config_zero = theme.ColoredParameter(
    "hexdump-zero-color", "red", "color for hexdump command (zero bytes)"
)
config_special = theme.ColoredParameter(
    "hexdump-special-color", "yellow", "color for hexdump command (special bytes)"
)
config_offset = theme.ColoredParameter(
    "hexdump-offset-color", "none", "color for hexdump command (offset label)"
)
config_address = theme.ColoredParameter(
    "hexdump-address-color", "none", "color for hexdump command (address label)"
)
config_separator = theme.ColoredParameter(
    "hexdump-separator-color", "none", "color for hexdump command (group separator)"
)
config_highlight_group_lsb = theme.Parameter(
    "hexdump-highlight-group-lsb",
    "underline",
    "highlight LSB of each group. Applies only if hexdump-adjust-group-endianess"
    " actually changes byte order.",
)


def normal(x):
    return generateColorFunction(config.hexdump_normal_color)(x)


def printable(x):
    return generateColorFunction(config.hexdump_printable_color)(x)


def zero(x):
    return generateColorFunction(config.hexdump_zero_color)(x)


def special(x):
    return generateColorFunction(config.hexdump_special_color)(x)


def offset(x):
    return generateColorFunction(config.hexdump_offset_color)(x)


def address(x):
    return generateColorFunction(config.hexdump_address_color)(x)


def separator(x):
    return generateColorFunction(config.hexdump_separator_color)(x)


def highlight_group_lsb(x):
    return generateColorFunction(config.hexdump_highlight_group_lsb)(x)


def colorize_ascii(c):
    c = chr(c)

    # TODO: Can we simplify this if statement?
    if not config.hexdump_colorize_ascii:
        if c in printable_chars:
            return c
        else:
            return "."

    if c in printable_chars:
        return printable(c)
    elif c == "\x00":
        return zero(".")
    elif c in ["\xff", "\x7f", "\x80"]:
        return special(".")

    # TODO: Should we return normal(".") or "."?
    return normal(".")

    # TODO:
    # printable[-1] = " "


def colorize_hex(c):
    x = "{:02x}".format(c)
    c = chr(c)

    # TODO: This logic can be shared with colorize_ascii
    if c in printable_chars:
        return printable(x)
    elif c == "\x00":
        return zero(x)
    elif c in ["\xff", "\x7f", "\x80"]:
        return special(x)

    return normal(x)

    # TODO:
    # color_scheme[-1] = "  "
