import os
import sys
import stat
import select
import time
import errno
try:
    InterruptedError
except NameError:
    InterruptedError = select.error
if sys.version_info[0] >= 3:
    string_types = (str,)
else:
    string_types = (unicode, str)

def is_executable_file(path):
    """Checks that path is an executable regular file, or a symlink towards one.

    This is roughly ``os.path isfile(path) and os.access(path, os.X_OK)``.
    """
    return os.path.isfile(path) and os.access(path, os.X_OK)

def which(filename, env=None):
    """This takes a given filename; tries to find it in the environment path;
    then checks if it is executable. This returns the full path to the filename
    if found and executable. Otherwise this returns None."""
    if env is None:
        env = os.environ
    
    path = env.get('PATH', '')
    for directory in path.split(os.pathsep):
        full_path = os.path.join(directory, filename)
        if is_executable_file(full_path):
            return full_path
    return None

def split_command_line(command_line):
    """This splits a command line into a list of arguments. It splits arguments
    on spaces, but handles embedded quotes, doublequotes, and escaped
    characters. It's impossible to do this with a regular expression, so I
    wrote a little state machine to parse the command line. """
    args = []
    current_arg = []
    state = 'normal'
    quote_char = None
    
    for char in command_line:
        if state == 'normal':
            if char.isspace():
                if current_arg:
                    args.append(''.join(current_arg))
                    current_arg = []
            elif char in ('"', "'"):
                state = 'in_quote'
                quote_char = char
            elif char == '\\':
                state = 'escaped'
            else:
                current_arg.append(char)
        elif state == 'in_quote':
            if char == quote_char:
                state = 'normal'
            else:
                current_arg.append(char)
        elif state == 'escaped':
            current_arg.append(char)
            state = 'normal'
    
    if current_arg:
        args.append(''.join(current_arg))
    
    return args

def select_ignore_interrupts(iwtd, owtd, ewtd, timeout=None):
    """This is a wrapper around select.select() that ignores signals. If
    select.select raises a select.error exception and errno is an EINTR
    error then it is ignored. Mainly this is used to ignore sigwinch
    (terminal resize). """
    while True:
        try:
            return select.select(iwtd, owtd, ewtd, timeout)
        except (select.error, InterruptedError) as e:
            if e.args[0] != errno.EINTR:
                raise

def poll_ignore_interrupts(fds, timeout=None):
    """Simple wrapper around poll to register file descriptors and
    ignore signals."""
    poller = select.poll()
    for fd in fds:
        poller.register(fd, select.POLLIN)
    
    while True:
        try:
            return poller.poll(timeout)
        except (select.error, InterruptedError) as e:
            if e.args[0] != errno.EINTR:
                raise
