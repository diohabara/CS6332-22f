#!/usr/bin/env python3

from pwn import *
from pwn import gdb

io = gdb.debug(
    "./malware",
    """
    break input_func
    """,
    log_level="debug",
)
