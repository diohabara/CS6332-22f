from pwn import *
from pwn import gdb

io = gdb.debug(
    "./malware",
    """
    # set breakpoint at password
    break password
    continue
    """,
    log_level="debug",
)
