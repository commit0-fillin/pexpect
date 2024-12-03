from io import StringIO, BytesIO
import codecs
import os
import sys
import re
import errno
from .exceptions import ExceptionPexpect, EOF, TIMEOUT
from .expect import Expecter, searcher_string, searcher_re
PY3 = sys.version_info[0] >= 3
text_type = str if PY3 else unicode

class _NullCoder(object):
    """Pass bytes through unchanged."""

class SpawnBase(object):
    """A base class providing the backwards-compatible spawn API for Pexpect.

    This should not be instantiated directly: use :class:`pexpect.spawn` or
    :class:`pexpect.fdpexpect.fdspawn`.
    """
    encoding = None
    pid = None
    flag_eof = False

    def __init__(self, timeout=30, maxread=2000, searchwindowsize=None, logfile=None, encoding=None, codec_errors='strict'):
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        self.searcher = None
        self.ignorecase = False
        self.before = None
        self.after = None
        self.match = None
        self.match_index = None
        self.terminated = True
        self.exitstatus = None
        self.signalstatus = None
        self.status = None
        self.child_fd = -1
        self.timeout = timeout
        self.delimiter = EOF
        self.logfile = logfile
        self.logfile_read = None
        self.logfile_send = None
        self.maxread = maxread
        self.searchwindowsize = searchwindowsize
        self.delaybeforesend = 0.05
        self.delayafterclose = 0.1
        self.delayafterterminate = 0.1
        self.delayafterread = 0.0001
        self.softspace = False
        self.name = '<' + repr(self) + '>'
        self.closed = True
        self.encoding = encoding
        self.codec_errors = codec_errors
        if encoding is None:
            self._encoder = self._decoder = _NullCoder()
            self.string_type = bytes
            self.buffer_type = BytesIO
            self.crlf = b'\r\n'
            if PY3:
                self.allowed_string_types = (bytes, str)
                self.linesep = os.linesep.encode('ascii')

                def write_to_stdout(b):
                    try:
                        return sys.stdout.buffer.write(b)
                    except AttributeError:
                        return sys.stdout.write(b.decode('ascii', 'replace'))
                self.write_to_stdout = write_to_stdout
            else:
                self.allowed_string_types = (basestring,)
                self.linesep = os.linesep
                self.write_to_stdout = sys.stdout.write
        else:
            self._encoder = codecs.getincrementalencoder(encoding)(codec_errors)
            self._decoder = codecs.getincrementaldecoder(encoding)(codec_errors)
            self.string_type = text_type
            self.buffer_type = StringIO
            self.crlf = u'\r\n'
            self.allowed_string_types = (text_type,)
            if PY3:
                self.linesep = os.linesep
            else:
                self.linesep = os.linesep.decode('ascii')
            self.write_to_stdout = sys.stdout.write
        self.async_pw_transport = None
        self._buffer = self.buffer_type()
        self._before = self.buffer_type()
    buffer = property(_get_buffer, _set_buffer)

    def read_nonblocking(self, size=1, timeout=None):
        """This reads data from the file descriptor.

        This is a simple implementation suitable for a regular file. Subclasses using ptys or pipes should override it.

        The timeout parameter is ignored.
        """
        if self.closed:
            raise ValueError('I/O operation on closed file')
        
        try:
            s = os.read(self.child_fd, size)
        except OSError as err:
            if err.args[0] == errno.EIO:
                # Linux-style EOF
                self.flag_eof = True
                raise EOF('End Of File (EOF). Exception style platform.')
            raise
        
        if s == b'':
            # BSD-style EOF
            self.flag_eof = True
            raise EOF('End Of File (EOF). Empty string style platform.')
        
        return self._decoder.decode(s, final=False)

    def compile_pattern_list(self, patterns):
        """This compiles a pattern-string or a list of pattern-strings.
        Patterns must be a StringType, EOF, TIMEOUT, SRE_Pattern, or a list of
        those. Patterns may also be None which results in an empty list (you
        might do this if waiting for an EOF or TIMEOUT condition without
        expecting any pattern).

        This is used by expect() when calling expect_list(). Thus expect() is
        nothing more than::

             cpl = self.compile_pattern_list(pl)
             return self.expect_list(cpl, timeout)

        If you are using expect() within a loop it may be more
        efficient to compile the patterns first and then call expect_list().
        This avoid calls in a loop to compile_pattern_list()::

             cpl = self.compile_pattern_list(my_pattern)
             while some_condition:
                ...
                i = self.expect_list(cpl, timeout)
                ...
        """
        if patterns is None:
            return []
        if not isinstance(patterns, list):
            patterns = [patterns]

        compiled_pattern_list = []
        for p in patterns:
            if isinstance(p, self.string_type):
                compiled_pattern_list.append(re.compile(p, re.DOTALL))
            elif p is EOF:
                compiled_pattern_list.append(EOF)
            elif p is TIMEOUT:
                compiled_pattern_list.append(TIMEOUT)
            elif isinstance(p, type(re.compile(''))):
                compiled_pattern_list.append(p)
            else:
                raise TypeError('Argument must be one of StringTypes, EOF, TIMEOUT, SRE_Pattern, or a list of those type. %s' % str(type(p)))

        return compiled_pattern_list

    def expect(self, pattern, timeout=-1, searchwindowsize=-1, async_=False, **kw):
        """This seeks through the stream until a pattern is matched. The
        pattern is overloaded and may take several types. The pattern can be a
        StringType, EOF, a compiled re, or a list of any of those types.
        Strings will be compiled to re types. This returns the index into the
        pattern list. If the pattern was not a list this returns index 0 on a
        successful match. This may raise exceptions for EOF or TIMEOUT. To
        avoid the EOF or TIMEOUT exceptions add EOF or TIMEOUT to the pattern
        list. That will cause expect to match an EOF or TIMEOUT condition
        instead of raising an exception.

        If you pass a list of patterns and more than one matches, the first
        match in the stream is chosen. If more than one pattern matches at that
        point, the leftmost in the pattern list is chosen. For example::

            # the input is 'foobar'
            index = p.expect(['bar', 'foo', 'foobar'])
            # returns 1('foo') even though 'foobar' is a "better" match

        Please note, however, that buffering can affect this behavior, since
        input arrives in unpredictable chunks. For example::

            # the input is 'foobar'
            index = p.expect(['foobar', 'foo'])
            # returns 0('foobar') if all input is available at once,
            # but returns 1('foo') if parts of the final 'bar' arrive late

        When a match is found for the given pattern, the class instance
        attribute *match* becomes an re.MatchObject result.  Should an EOF
        or TIMEOUT pattern match, then the match attribute will be an instance
        of that exception class.  The pairing before and after class
        instance attributes are views of the data preceding and following
        the matching pattern.  On general exception, class attribute
        *before* is all data received up to the exception, while *match* and
        *after* attributes are value None.

        When the keyword argument timeout is -1 (default), then TIMEOUT will
        raise after the default value specified by the class timeout
        attribute. When None, TIMEOUT will not be raised and may block
        indefinitely until match.

        When the keyword argument searchwindowsize is -1 (default), then the
        value specified by the class maxread attribute is used.

        A list entry may be EOF or TIMEOUT instead of a string. This will
        catch these exceptions and return the index of the list entry instead
        of raising the exception. The attribute 'after' will be set to the
        exception type. The attribute 'match' will be None. This allows you to
        write code like this::

                index = p.expect(['good', 'bad', pexpect.EOF, pexpect.TIMEOUT])
                if index == 0:
                    do_something()
                elif index == 1:
                    do_something_else()
                elif index == 2:
                    do_some_other_thing()
                elif index == 3:
                    do_something_completely_different()

        instead of code like this::

                try:
                    index = p.expect(['good', 'bad'])
                    if index == 0:
                        do_something()
                    elif index == 1:
                        do_something_else()
                except EOF:
                    do_some_other_thing()
                except TIMEOUT:
                    do_something_completely_different()

        These two forms are equivalent. It all depends on what you want. You
        can also just expect the EOF if you are waiting for all output of a
        child to finish. For example::

                p = pexpect.spawn('/bin/ls')
                p.expect(pexpect.EOF)
                print p.before

        If you are trying to optimize for speed then see expect_list().

        On Python 3.4, or Python 3.3 with asyncio installed, passing
        ``async_=True``  will make this return an :mod:`asyncio` coroutine,
        which you can yield from to get the same result that this method would
        normally give directly. So, inside a coroutine, you can replace this code::

            index = p.expect(patterns)

        With this non-blocking form::

            index = yield from p.expect(patterns, async_=True)
        """
        compiled_pattern_list = self.compile_pattern_list(pattern)
        return self.expect_list(compiled_pattern_list,
                                timeout,
                                searchwindowsize,
                                async_)

    def expect_list(self, pattern_list, timeout=-1, searchwindowsize=-1, async_=False, **kw):
        """This takes a list of compiled regular expressions and returns the
        index into the pattern_list that matched the child output. The list may
        also contain EOF or TIMEOUT(which are not compiled regular
        expressions). This method is similar to the expect() method except that
        expect_list() does not recompile the pattern list on every call. This
        may help if you are trying to optimize for speed, otherwise just use
        the expect() method.  This is called by expect().


        Like :meth:`expect`, passing ``async_=True`` will make this return an
        asyncio coroutine.
        """
        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout
        if searchwindowsize == -1:
            searchwindowsize = self.searchwindowsize

        exp = Expecter(self, pattern_list, searchwindowsize)
        if async_:
            if not isinstance(self, PexpectSpawnBase):
                raise TypeError('This SpawnBase does not support async operations')
            return self._expect_async(exp, timeout, async_=True)

        try:
            idx = exp.expect_loop(timeout)
            return idx
        except EOF as e:
            self.flag_eof = True
            raise EOF(str(e) + '\n' + str(self))
        except TIMEOUT as e:
            raise TIMEOUT(str(e) + '\n' + str(self))
        except:
            self.close()
            raise

    def expect_exact(self, pattern_list, timeout=-1, searchwindowsize=-1, async_=False, **kw):
        """This is similar to expect(), but uses plain string matching instead
        of compiled regular expressions in 'pattern_list'. The 'pattern_list'
        may be a string; a list or other sequence of strings; or TIMEOUT and
        EOF.

        This call might be faster than expect() for two reasons: string
        searching is faster than RE matching and it is possible to limit the
        search to just the end of the input buffer.

        This method is also useful when you don't want to have to worry about
        escaping regular expression characters that you want to match.

        Like :meth:`expect`, passing ``async_=True`` will make this return an
        asyncio coroutine.
        """
        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout
        if searchwindowsize == -1:
            searchwindowsize = self.searchwindowsize

        if isinstance(pattern_list, self.string_type):
            pattern_list = [pattern_list]

        exp = searcher_string(pattern_list)
        try:
            idx = self.expect_loop(exp, timeout, searchwindowsize)
            return idx
        except EOF as e:
            self.flag_eof = True
            raise EOF(str(e) + '\n' + str(self))
        except TIMEOUT as e:
            raise TIMEOUT(str(e) + '\n' + str(self))

    def expect_loop(self, searcher, timeout=-1, searchwindowsize=-1):
        """This is the common loop used inside expect. The 'searcher' should be
        an instance of searcher_re or searcher_string, which describes how and
        what to search for in the input.

        See expect() for other arguments, return value and exceptions. """
        self.searcher = searcher

        if timeout == -1:
            timeout = self.timeout
        if timeout is not None:
            end_time = time.time() + timeout
        if searchwindowsize == -1:
            searchwindowsize = self.searchwindowsize

        try:
            incoming = self.buffer
            freshlen = len(incoming)
            while True:
                idx = searcher.search(incoming, freshlen, searchwindowsize)
                if idx >= 0:
                    self.buffer = incoming[searcher.end:]
                    self.before = incoming[:searcher.start]
                    self.after = incoming[searcher.start:searcher.end]
                    self.match = searcher.match
                    self.match_index = idx
                    return idx
                # No match
                if timeout is not None and time.time() > end_time:
                    raise TIMEOUT('Timeout exceeded in expect_loop.')
                # Still have time left, so read more data
                c = self.read_nonblocking(self.maxread, timeout)
                freshlen = len(c)
                time.sleep(0.0001)
                incoming = incoming + c
                if timeout is not None:
                    timeout = end_time - time.time()
        except EOF:
            self.buffer = self.string_type()
            self.before = incoming
            self.after = EOF
            index = searcher.eof_index
            if index >= 0:
                self.match = EOF
                self.match_index = index
                return index
            else:
                self.match = None
                self.match_index = None
                raise EOF('EOF encountered in expect_loop')
        except TIMEOUT:
            self.buffer = incoming
            self.before = incoming
            self.after = TIMEOUT
            index = searcher.timeout_index
            if index >= 0:
                self.match = TIMEOUT
                self.match_index = index
                return index
            else:
                self.match = None
                self.match_index = None
                raise TIMEOUT('Timeout encountered in expect_loop')
        except:
            self.before = incoming
            self.after = None
            self.match = None
            self.match_index = None
            raise

    def read(self, size=-1):
        """This reads at most "size" bytes from the file (less if the read hits
        EOF before obtaining size bytes). If the size argument is negative or
        omitted, read all data until EOF is reached. The bytes are returned as
        a string object. An empty string is returned when EOF is encountered
        immediately. """
        if size < 0:
            self.expect(EOF)
            return self.before

        result = self.string_type()
        while len(result) < size:
            try:
                result += self.read_nonblocking(size - len(result))
            except EOF:
                break
        return result

    def readline(self, size=-1):
        """This reads and returns one entire line. The newline at the end of
        line is returned as part of the string, unless the file ends without a
        newline. An empty string is returned if EOF is encountered immediately.
        This looks for a newline as a CR/LF pair (\\r\\n) even on UNIX because
        this is what the pseudotty device returns. So contrary to what you may
        expect you will receive newlines as \\r\\n.

        If the size argument is 0 then an empty string is returned. In all
        other cases the size argument is ignored, which is not standard
        behavior for a file-like object. """
        if size == 0:
            return self.string_type()
        index = self.expect(['\r\n', EOF])
        if index == 0:
            return self.before + '\r\n'
        else:
            return self.before

    def __iter__(self):
        """This is to support iterators over a file-like object.
        """
        return iter(self.readline, self.string_type())

    def readlines(self, sizehint=-1):
        """This reads until EOF using readline() and returns a list containing
        the lines thus read. The optional 'sizehint' argument is ignored.
        Remember, because this reads until EOF that means the child
        process should have closed its stdout. If you run this method on
        a child that is still running with its stdout open then this
        method will block until it timesout."""
        lines = []
        while True:
            line = self.readline()
            if not line:
                break
            lines.append(line)
        return lines

    def fileno(self):
        """Expose file descriptor for a file-like interface
        """
        return self.child_fd

    def flush(self):
        """This does nothing. It is here to support the interface for a
        File-like object. """
        pass

    def isatty(self):
        """Overridden in subclass using tty"""
        return False

    def __enter__(self):
        return self

    def __exit__(self, etype, evalue, tb):
        self.close()
