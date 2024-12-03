import sys
import types
from .exceptions import EOF, TIMEOUT
from .pty_spawn import spawn

def run(command, timeout=30, withexitstatus=False, events=None, extra_args=None, logfile=None, cwd=None, env=None, **kwargs):
    """
    This function runs the given command; waits for it to finish; then
    returns all output as a string. STDERR is included in output. If the full
    path to the command is not given then the path is searched.

    Note that lines are terminated by CR/LF (\\r\\n) combination even on
    UNIX-like systems because this is the standard for pseudottys. If you set
    'withexitstatus' to true, then run will return a tuple of (command_output,
    exitstatus). If 'withexitstatus' is false then this returns just
    command_output.

    The run() function can often be used instead of creating a spawn instance.
    For example, the following code uses spawn::

        from pexpect import *
        child = spawn('scp foo user@example.com:.')
        child.expect('(?i)password')
        child.sendline(mypassword)

    The previous code can be replace with the following::

        from pexpect import *
        run('scp foo user@example.com:.', events={'(?i)password': mypassword})

    **Examples**

    Start the apache daemon on the local machine::

        from pexpect import *
        run("/usr/local/apache/bin/apachectl start")

    Check in a file using SVN::

        from pexpect import *
        run("svn ci -m 'automatic commit' my_file.py")

    Run a command and capture exit status::

        from pexpect import *
        (command_output, exitstatus) = run('ls -l /bin', withexitstatus=1)

    The following will run SSH and execute 'ls -l' on the remote machine. The
    password 'secret' will be sent if the '(?i)password' pattern is ever seen::

        run("ssh username@machine.example.com 'ls -l'",
            events={'(?i)password':'secret\\n'})

    This will start mencoder to rip a video from DVD. This will also display
    progress ticks every 5 seconds as it runs. For example::

        from pexpect import *
        def print_ticks(d):
            print d['event_count'],
        run("mencoder dvd://1 -o video.avi -oac copy -ovc copy",
            events={TIMEOUT:print_ticks}, timeout=5)

    The 'events' argument should be either a dictionary or a tuple list that
    contains patterns and responses. Whenever one of the patterns is seen
    in the command output, run() will send the associated response string.
    So, run() in the above example can be also written as::

        run("mencoder dvd://1 -o video.avi -oac copy -ovc copy",
            events=[(TIMEOUT,print_ticks)], timeout=5)

    Use a tuple list for events if the command output requires a delicate
    control over what pattern should be matched, since the tuple list is passed
    to pexpect() as its pattern list, with the order of patterns preserved.

    Note that you should put newlines in your string if Enter is necessary.

    Like the example above, the responses may also contain a callback, either
    a function or method.  It should accept a dictionary value as an argument.
    The dictionary contains all the locals from the run() function, so you can
    access the child spawn object or any other variable defined in run()
    (event_count, child, and extra_args are the most useful). A callback may
    return True to stop the current run process.  Otherwise run() continues
    until the next event. A callback may also return a string which will be
    sent to the child. 'extra_args' is not used by directly run(). It provides
    a way to pass data to a callback function through run() through the locals
    dictionary passed to a callback.

    Like :class:`spawn`, passing *encoding* will make it work with unicode
    instead of bytes. You can pass *codec_errors* to control how errors in
    encoding and decoding are handled.
    """
    # Import necessary modules
    from .spawn import spawn
    from .exceptions import ExceptionPexpect, TIMEOUT, EOF

    # Create a new spawn instance
    child = spawn(command, timeout=timeout, maxread=2000, logfile=logfile, cwd=cwd, env=env, **kwargs)

    # Initialize variables
    output = ""
    event_count = 0

    # Process events
    if events is not None:
        if isinstance(events, dict):
            events = list(events.items())
        elif not isinstance(events, list):
            raise TypeError('events must be a dictionary or list of tuples')

    try:
        while True:
            try:
                index = child.expect([EOF, TIMEOUT] + [x for x, y in events])
                if index == 0:  # EOF
                    break
                elif index == 1:  # TIMEOUT
                    if events is None:
                        break
                    event_count += 1
                    response = events[index - 2][1]
                else:
                    event_count += 1
                    response = events[index - 2][1]

                if callable(response):
                    response = response({
                        'child': child,
                        'event_count': event_count,
                        'extra_args': extra_args
                    })

                if response is True:
                    break
                elif isinstance(response, str):
                    child.sendline(response)
                elif response is not None:
                    child.sendline(str(response))

            except TIMEOUT:
                break
            except EOF:
                break

        # Collect output
        output = child.before

        # Get exit status if requested
        if withexitstatus:
            child.close()
            exitstatus = child.exitstatus
            return (output, exitstatus)
        else:
            return output

    finally:
        # Ensure the child process is terminated
        if child.isalive():
            child.terminate()

def runu(command, timeout=30, withexitstatus=False, events=None, extra_args=None, logfile=None, cwd=None, env=None, **kwargs):
    """Deprecated: pass encoding to run() instead.
    """
    import warnings
    warnings.warn("runu() is deprecated. Use run() with encoding='utf-8' instead.",
                  DeprecationWarning, stacklevel=2)
    
    if 'encoding' not in kwargs:
        kwargs['encoding'] = 'utf-8'
    return run(command, timeout, withexitstatus, events, extra_args, logfile, cwd, env, **kwargs)
