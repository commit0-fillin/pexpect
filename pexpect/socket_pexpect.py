"""This is like :mod:`pexpect`, but it will work with any socket that you
pass it. You are responsible for opening and closing the socket.

PEXPECT LICENSE

    This license is approved by the OSI and FSF as GPL-compatible.
        http://opensource.org/licenses/isc-license.txt

    Copyright (c) 2012, Noah Spurrier <noah@noah.org>
    PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY
    PURPOSE WITH OR WITHOUT FEE IS HEREBY GRANTED, PROVIDED THAT THE ABOVE
    COPYRIGHT NOTICE AND THIS PERMISSION NOTICE APPEAR IN ALL COPIES.
    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
import socket
import select
from contextlib import contextmanager
from .exceptions import TIMEOUT, EOF
from .spawnbase import SpawnBase
__all__ = ['SocketSpawn']

class SocketSpawn(SpawnBase):
    """This is like :mod:`pexpect.fdpexpect` but uses the cross-platform python socket api,
    rather than the unix-specific file descriptor api. Thus, it works with
    remote connections on both unix and windows."""

    def __init__(self, socket: socket.socket, args=None, timeout=30, maxread=2000, searchwindowsize=None, logfile=None, encoding=None, codec_errors='strict', use_poll=False):
        """This takes an open socket."""
        self.args = None
        self.command = None
        SpawnBase.__init__(self, timeout, maxread, searchwindowsize, logfile, encoding=encoding, codec_errors=codec_errors)
        self.socket = socket
        self.child_fd = socket.fileno()
        self.closed = False
        self.name = '<socket %s>' % socket
        self.use_poll = use_poll

    def close(self):
        """Close the socket.

        Calling this method a second time does nothing, but if the file
        descriptor was closed elsewhere, :class:`OSError` will be raised.
        """
        if not self.closed:
            self.socket.close()
            self.closed = True

    def isalive(self):
        """ Alive if the fileno is valid """
        if self.closed:
            return False
        try:
            self.socket.getpeername()
            return True
        except socket.error:
            return False

    def send(self, s) -> int:
        """Write to socket, return number of bytes written"""
        if isinstance(s, str):
            s = s.encode(self.encoding)
        return self.socket.send(s)

    def sendline(self, s) -> int:
        """Write to socket with trailing newline, return number of bytes written"""
        if isinstance(s, str):
            s = s.encode(self.encoding)
        return self.socket.send(s + self.linesep)

    def write(self, s):
        """Write to socket, return None"""
        if isinstance(s, str):
            s = s.encode(self.encoding)
        self.socket.sendall(s)

    def writelines(self, sequence):
        """Call self.write() for each item in sequence"""
        for item in sequence:
            self.write(item)

    def read_nonblocking(self, size=1, timeout=-1):
        """
        Read from the file descriptor and return the result as a string.

        The read_nonblocking method of :class:`SpawnBase` assumes that a call
        to os.read will not block (timeout parameter is ignored). This is not
        the case for POSIX file-like objects such as sockets and serial ports.

        Use :func:`select.select`, timeout is implemented conditionally for
        POSIX systems.

        :param int size: Read at most *size* bytes.
        :param int timeout: Wait timeout seconds for file descriptor to be
            ready to read. When -1 (default), use self.timeout. When 0, poll.
        :return: String containing the bytes read
        """
        if timeout == -1:
            timeout = self.timeout
        
        if self.closed:
            raise ValueError('I/O operation on closed file')

        try:
            ready, _, _ = select.select([self.socket], [], [], timeout)
            if not ready:
                raise TIMEOUT('Timeout exceeded in read_nonblocking.')
            
            data = self.socket.recv(size)
            if not data:
                self.flag_eof = True
                raise EOF('End Of File (EOF). Empty string style platform.')
            
            return self._decoder.decode(data, final=False)
        except socket.error as e:
            raise EOF('End Of File (EOF). Exception style platform.')
