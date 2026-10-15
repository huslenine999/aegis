"""Stop scanner subprocesses from reading the worker's secrets.

Scanner subprocesses run as the same OS user as the worker. By default Linux
lets a process read another same-user process's /proc/<pid>/environ and
/proc/<pid>/mem, which would expose the worker's database password and keys
to a hostile repository that compromises a scanner, even though scanners
themselves receive a stripped environment. Marking the worker non-dumpable
makes those files readable only by root. Forked RQ work horses inherit the
flag; exec'd scanner processes do not, so they keep working normally.
"""

import ctypes
import ctypes.util
import sys

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3


def deny_same_user_inspection() -> bool:
    """Mark this process non-dumpable. Returns True when the flag is in effect."""
    if not sys.platform.startswith("linux"):
        return False
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE, 0) failed")
    return libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
