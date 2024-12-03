"""This is like :mod:`pexpect`, but it will work with any file descriptor that you
pass it. You are responsible for opening and close the file descriptor.
This allows you to use Pexpect with sockets and named pipes (FIFOs).

.. note::
    socket.fileno() does not give a readable file descriptor on windows.
    Use :mod:`pexpect.socket_pexpect` for cross-platform socket support

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
from .spawnbase import SpawnBase
from .exceptions import ExceptionPexpect, TIMEOUT
from .utils import select_ignore_interrupts, poll_ignore_interrupts
import os
__all__ = ['fdspawn']

class fdspawn(SpawnBase):
    """This is like pexpect.spawn but allows you to supply your own open file
    descriptor. For example, you could use it to read through a file looking
    for patterns, or to control a modem or serial device. """

    def __init__(self, fd, args=None, timeout=30, maxread=2000, searchwindowsize=None, logfile=None, encoding=None, codec_errors='strict', use_poll=False):
        """This takes a file descriptor (an int) or an object that support the
        fileno() method (returning an int). All Python file-like objects
        support fileno(). """
        if type(fd) != type(0) and hasattr(fd, 'fileno'):
            fd = fd.fileno()
        if type(fd) != type(0):
            raise ExceptionPexpect('The fd argument is not an int. If this is a command string then maybe you want to use pexpect.spawn.')
        try:
            os.fstat(fd)
        except OSError:
            raise ExceptionPexpect('The fd argument is not a valid file descriptor.')
        self.args = None
        self.command = None
        SpawnBase.__init__(self, timeout, maxread, searchwindowsize, logfile, encoding=encoding, codec_errors=codec_errors)
        self.child_fd = fd
        self.own_fd = False
        self.closed = False
        self.name = '<file descriptor %d>' % fd
        self.use_poll = use_poll

    def close(self):
        """Close the file descriptor.

        Calling this method a second time does nothing, but if the file
        descriptor was closed elsewhere, :class:`OSError` will be raised.
        """
        if not self.closed:
            os.close(self.child_fd)
            self.closed = True

    def isalive(self):
        """This checks if the file descriptor is still valid. If :func:`os.fstat`
        does not raise an exception then we assume it is alive. """
        if self.closed:
            return False
        try:
            os.fstat(self.child_fd)
            return True
        except OSError:
            return False

    def terminate(self, force=False):
        """Deprecated and invalid. Just raises an exception."""
        raise ExceptionPexpect('This method is not valid for file descriptors.')

    def send(self, s):
        """Write to fd, return number of bytes written"""
        if not self.isatty() and isinstance(s, self.string_type):
            s = s.encode(self.encoding)
        return os.write(self.child_fd, s)

    def sendline(self, s):
        """Write to fd with trailing newline, return number of bytes written"""
        n = self.send(s)
        n += self.send(self.linesep)
        return n

    def write(self, s):
        """Write to fd, return None"""
        self.send(s)

    def writelines(self, sequence):
        """Call self.write() for each item in sequence"""
        for s in sequence:
            self.write(s)

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
        
        if timeout is not None:
            end_time = time.time() + timeout
        
        if self.use_poll:
            poller = select.poll()
            poller.register(self.child_fd, select.POLLIN)
        
        while True:
            try:
                if self.use_poll:
                    events = poller.poll(timeout * 1000 if timeout is not None else None)
                    if not events:
                        raise TIMEOUT('Timeout exceeded in read_nonblocking().')
                else:
                    rlist, _, _ = select_ignore_interrupts([self.child_fd], [], [], timeout)
                    if not rlist:
                        raise TIMEOUT('Timeout exceeded in read_nonblocking().')
                
                s = os.read(self.child_fd, size)
                if s == b'':
                    self.flag_eof = True
                    raise EOF('EOF encountered in read_nonblocking().')
                return self._decoder.decode(s, final=False)
            except InterruptedError:
                if timeout is not None:
                    timeout = end_time - time.time()
                    if timeout <= 0:
                        raise TIMEOUT('Timeout exceeded in read_nonblocking().')
