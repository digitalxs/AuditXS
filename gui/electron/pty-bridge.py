#!/usr/bin/env python3
"""
AuditXS — PTY bridge for the Electron embedded terminal.

A dependency-free pseudo-terminal broker so the Electron app can host a real,
fully interactive terminal (xterm.js in the renderer) without a native Node
module (node-pty). It uses only the Python standard library — and Python is
already an AuditXS dependency (the web UI needs it).

Wiring (all set up by the Electron main process):

  * fd 0 (stdin)  — raw keystrokes from xterm.js are written to the PTY master.
  * fd 1 (stdout) — raw PTY output is copied here for xterm.js to render.
  * fd 3          — optional control channel: newline-delimited JSON, e.g.
                    {"resize":[cols,rows]} to propagate window-size changes.

It forks the user's login shell ($SHELL, else /bin/bash) on the PTY slave and
brokers bytes until the shell exits or stdin closes. Because it runs with the
Electron process's own (unprivileged) rights, it is exactly a terminal the user
could have opened themselves — no privilege is added here.
"""
import json
import os
import pty
import select
import struct
import sys

try:
    import fcntl
    import termios
    _HAVE_WINSZ = True
except ImportError:                       # non-POSIX; the app never ships there
    _HAVE_WINSZ = False


def _set_winsize(fd, cols, rows):
    if not _HAVE_WINSZ:
        return
    try:
        ws = struct.pack("HHHH", max(1, int(rows)), max(1, int(cols)), 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, ws)
    except (OSError, ValueError, struct.error):
        pass


def _ctrl_fd_open():
    """True when fd 3 was handed to us as a readable control channel."""
    try:
        os.fstat(3)
        return True
    except OSError:
        return False


def main():
    shell = os.environ.get("SHELL") or "/bin/bash"
    # A sane default environment for an interactive shell.
    os.environ.setdefault("TERM", "xterm-256color")

    pid, master = pty.fork()
    if pid == 0:
        # Child: become the interactive shell. As a login-ish interactive shell
        # so profiles load and the user feels at home.
        try:
            os.execvp(shell, [shell, "-i"])
        except OSError:
            os.execvp("/bin/sh", ["/bin/sh"])
        os._exit(127)                     # unreachable

    # Parent: broker bytes between the PTY master and our stdio.
    has_ctrl = _ctrl_fd_open()
    ctrl_buf = ""
    watch = [master, 0] + ([3] if has_ctrl else [])

    while True:
        try:
            readable, _, _ = select.select(watch, [], [])
        except (OSError, select.error):
            break

        if master in readable:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if not data:
                break                      # shell exited
            try:
                os.write(1, data)
            except OSError:
                break

        if 0 in readable:
            try:
                data = os.read(0, 65536)
            except OSError:
                data = b""
            if not data:
                break                      # stdin closed → tear down
            try:
                os.write(master, data)
            except OSError:
                break

        if has_ctrl and 3 in readable:
            try:
                chunk = os.read(3, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                has_ctrl = False
                watch = [master, 0]
            else:
                ctrl_buf += chunk.decode("utf-8", "replace")
                while "\n" in ctrl_buf:
                    line, ctrl_buf = ctrl_buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(msg, dict) and "resize" in msg:
                        try:
                            cols, rows = msg["resize"]
                            _set_winsize(master, cols, rows)
                        except (TypeError, ValueError):
                            pass

    try:
        os.close(master)
    except OSError:
        pass
    try:
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else 0
    except OSError:
        code = 0
    sys.exit(code if isinstance(code, int) and code >= 0 else 0)


if __name__ == "__main__":
    main()
