"""Tiny helper shared by the lab scripts: print() that wraps long lines.

The report prints each script's output verbatim in a fixed-width box, so every line is kept
within WIDTH columns; a wrapped continuation line is indented by four extra spaces.
"""
import textwrap

WIDTH = 96


def say(*args):
    text = " ".join(str(a) for a in args)
    for line in text.split("\n"):
        if len(line) <= WIDTH:
            print(line)
            continue
        indent = " " * (len(line) - len(line.lstrip(" ")))
        print(textwrap.fill(line, WIDTH, subsequent_indent=indent + "    ",
                            break_long_words=False, break_on_hyphens=False))
