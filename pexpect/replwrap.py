"""Generic wrapper for read-eval-print-loops, a.k.a. interactive shells
"""
import os.path
import signal
import sys
import pexpect
PY3 = sys.version_info[0] >= 3
if PY3:
    basestring = str
PEXPECT_PROMPT = u'[PEXPECT_PROMPT>'
PEXPECT_CONTINUATION_PROMPT = u'[PEXPECT_PROMPT+'

class REPLWrapper(object):
    """Wrapper for a REPL.

    :param cmd_or_spawn: This can either be an instance of :class:`pexpect.spawn`
      in which a REPL has already been started, or a str command to start a new
      REPL process.
    :param str orig_prompt: The prompt to expect at first.
    :param str prompt_change: A command to change the prompt to something more
      unique. If this is ``None``, the prompt will not be changed. This will
      be formatted with the new and continuation prompts as positional
      parameters, so you can use ``{}`` style formatting to insert them into
      the command.
    :param str new_prompt: The more unique prompt to expect after the change.
    :param str extra_init_cmd: Commands to do extra initialisation, such as
      disabling pagers.
    """

    def __init__(self, cmd_or_spawn, orig_prompt, prompt_change, new_prompt=PEXPECT_PROMPT, continuation_prompt=PEXPECT_CONTINUATION_PROMPT, extra_init_cmd=None):
        if isinstance(cmd_or_spawn, basestring):
            self.child = pexpect.spawn(cmd_or_spawn, echo=False, encoding='utf-8')
        else:
            self.child = cmd_or_spawn
        if self.child.echo:
            self.child.setecho(False)
            self.child.waitnoecho()
        if prompt_change is None:
            self.prompt = orig_prompt
        else:
            self.set_prompt(orig_prompt, prompt_change.format(new_prompt, continuation_prompt))
            self.prompt = new_prompt
        self.continuation_prompt = continuation_prompt
        self._expect_prompt()
        if extra_init_cmd is not None:
            self.run_command(extra_init_cmd)

    def run_command(self, command, timeout=-1, async_=False):
        """Send a command to the REPL, wait for and return output.

        :param str command: The command to send. Trailing newlines are not needed.
          This should be a complete block of input that will trigger execution;
          if a continuation prompt is found after sending input, :exc:`ValueError`
          will be raised.
        :param int timeout: How long to wait for the next prompt. -1 means the
          default from the :class:`pexpect.spawn` object (default 30 seconds).
          None means to wait indefinitely.
        :param bool async_: On Python 3.4, or Python 3.3 with asyncio
          installed, passing ``async_=True`` will make this return an
          :mod:`asyncio` Future, which you can yield from to get the same
          result that this method would normally give directly.
        """
        if async_:
            import asyncio
            return asyncio.ensure_future(self._run_command_async(command, timeout))
        
        self.child.sendline(command)
        self._expect_prompt(timeout=timeout)
        
        # Remove the echoed command and the final prompt
        output = self.child.before.strip()
        output = output[len(command):].strip()
        return output

    async def _run_command_async(self, command, timeout):
        self.child.sendline(command)
        await self._expect_prompt_async(timeout=timeout)
        
        output = self.child.before.strip()
        output = output[len(command):].strip()
        return output

    def _expect_prompt(self, timeout=-1):
        return self.child.expect([self.prompt, self.continuation_prompt], timeout=timeout)

    async def _expect_prompt_async(self, timeout=-1):
        return await self.child.expect_async([self.prompt, self.continuation_prompt], timeout=timeout)

def python(command=sys.executable):
    """Start a Python shell and return a :class:`REPLWrapper` object."""
    orig_prompt = '>>> '
    prompt_change = 'import sys; sys.ps1={0!r}; sys.ps2={1!r}\n'
    return REPLWrapper(command, orig_prompt, prompt_change)

def bash(command='bash'):
    """Start a bash shell and return a :class:`REPLWrapper` object."""
    orig_prompt = r'[$#] '
    prompt_change = "PS1='{0}'; PS2='{1}'\n"
    extra_init_cmd = "export PAGER=cat\n"
    return REPLWrapper(command, orig_prompt, prompt_change, extra_init_cmd=extra_init_cmd)

def zsh(command='zsh', args=('--no-rcs', '-V', '+Z')):
    """Start a zsh shell and return a :class:`REPLWrapper` object."""
    orig_prompt = r'[%#] '
    prompt_change = r'PROMPT={0}; PROMPT2={1}\n'
    extra_init_cmd = "export PAGER=cat\n"
    cmd = ' '.join([command] + list(args))
    return REPLWrapper(cmd, orig_prompt, prompt_change, extra_init_cmd=extra_init_cmd)
