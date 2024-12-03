"""Provides an interface like pexpect.spawn interface using subprocess.Popen
"""
import os
import threading
import subprocess
import sys
import time
import signal
import shlex
try:
    from queue import Queue, Empty
except ImportError:
    from Queue import Queue, Empty
from .spawnbase import SpawnBase, PY3
from .exceptions import EOF
from .utils import string_types

class PopenSpawn(SpawnBase):

    def __init__(self, cmd, timeout=30, maxread=2000, searchwindowsize=None, logfile=None, cwd=None, env=None, encoding=None, codec_errors='strict', preexec_fn=None):
        super(PopenSpawn, self).__init__(timeout=timeout, maxread=maxread, searchwindowsize=searchwindowsize, logfile=logfile, encoding=encoding, codec_errors=codec_errors)
        if encoding is None:
            self.crlf = os.linesep.encode('ascii')
        else:
            self.crlf = self.string_type(os.linesep)
        kwargs = dict(bufsize=0, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, cwd=cwd, preexec_fn=preexec_fn, env=env)
        if sys.platform == 'win32':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kwargs['startupinfo'] = startupinfo
            kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
        if isinstance(cmd, string_types) and sys.platform != 'win32':
            cmd = shlex.split(cmd, posix=os.name == 'posix')
        self.proc = subprocess.Popen(cmd, **kwargs)
        self.pid = self.proc.pid
        self.closed = False
        self._buf = self.string_type()
        self._read_queue = Queue()
        self._read_thread = threading.Thread(target=self._read_incoming)
        self._read_thread.daemon = True
        self._read_thread.start()
    _read_reached_eof = False

    def _read_incoming(self):
        """Run in a thread to move output from a pipe to a queue."""
        while True:
            try:
                data = os.read(self.proc.stdout.fileno(), 1024)
                if data == b'':
                    self._read_reached_eof = True
                    break
                self._read_queue.put(data)
            except OSError as e:
                if e.errno != errno.EINTR:
                    break

    def write(self, s):
        """This is similar to send() except that there is no return value.
        """
        if not self.isalive():
            raise OSError("Child process is not alive.")
        if not isinstance(s, bytes):
            s = s.encode(self.encoding)
        self.proc.stdin.write(s)
        self.proc.stdin.flush()

    def writelines(self, sequence):
        """This calls write() for each element in the sequence.

        The sequence can be any iterable object producing strings, typically a
        list of strings. This does not add line separators. There is no return
        value.
        """
        for s in sequence:
            self.write(s)

    def send(self, s):
        """Send data to the subprocess' stdin.

        Returns the number of bytes written.
        """
        if not self.isalive():
            raise OSError("Child process is not alive.")
        if not isinstance(s, bytes):
            s = s.encode(self.encoding)
        return self.proc.stdin.write(s)

    def sendline(self, s=''):
        """Wraps send(), sending string ``s`` to child process, with os.linesep
        automatically appended. Returns number of bytes written. """
        n = self.send(s)
        return n + self.send(self.linesep)

    def wait(self):
        """Wait for the subprocess to finish.

        Returns the exit code.
        """
        return self.proc.wait()

    def kill(self, sig):
        """Sends a Unix signal to the subprocess.

        Use constants from the :mod:`signal` module to specify which signal.
        """
        if sys.platform != 'win32':
            os.kill(self.pid, sig)
        else:
            if sig == signal.SIGTERM:
                self.proc.terminate()
            elif sig == signal.SIGKILL:
                self.proc.kill()
            else:
                raise ValueError("On Windows, only SIGTERM and SIGKILL are supported.")

    def sendeof(self):
        """Closes the stdin pipe from the writing end."""
        self.proc.stdin.close()
