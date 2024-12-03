"""This implements an ANSI (VT100) terminal emulator as a subclass of screen.

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
from . import screen
from . import FSM
import string

class term(screen.screen):
    """This class is an abstract, generic terminal.
    This does nothing. This is a placeholder that
    provides a common base class for other terminals
    such as an ANSI terminal. """

    def __init__(self, r=24, c=80, *args, **kwargs):
        screen.screen.__init__(self, r, c, *args, **kwargs)

class ANSI(term):
    """This class implements an ANSI (VT100) terminal.
    It is a stream filter that recognizes ANSI terminal
    escape sequences and maintains the state of a screen object. """

    def __init__(self, r=24, c=80, *args, **kwargs):
        term.__init__(self, r, c, *args, **kwargs)
        self.state = FSM.FSM('INIT', [self])
        self.state.set_default_transition(DoLog, 'INIT')
        self.state.add_transition_any('INIT', DoEmit, 'INIT')
        self.state.add_transition('\x1b', 'INIT', None, 'ESC')
        self.state.add_transition_any('ESC', DoLog, 'INIT')
        self.state.add_transition('(', 'ESC', None, 'G0SCS')
        self.state.add_transition(')', 'ESC', None, 'G1SCS')
        self.state.add_transition_list('AB012', 'G0SCS', None, 'INIT')
        self.state.add_transition_list('AB012', 'G1SCS', None, 'INIT')
        self.state.add_transition('7', 'ESC', DoCursorSave, 'INIT')
        self.state.add_transition('8', 'ESC', DoCursorRestore, 'INIT')
        self.state.add_transition('M', 'ESC', DoUpReverse, 'INIT')
        self.state.add_transition('>', 'ESC', DoUpReverse, 'INIT')
        self.state.add_transition('<', 'ESC', DoUpReverse, 'INIT')
        self.state.add_transition('=', 'ESC', None, 'INIT')
        self.state.add_transition('#', 'ESC', None, 'GRAPHICS_POUND')
        self.state.add_transition_any('GRAPHICS_POUND', None, 'INIT')
        self.state.add_transition('[', 'ESC', None, 'ELB')
        self.state.add_transition('H', 'ELB', DoHomeOrigin, 'INIT')
        self.state.add_transition('D', 'ELB', DoBackOne, 'INIT')
        self.state.add_transition('B', 'ELB', DoDownOne, 'INIT')
        self.state.add_transition('C', 'ELB', DoForwardOne, 'INIT')
        self.state.add_transition('A', 'ELB', DoUpOne, 'INIT')
        self.state.add_transition('J', 'ELB', DoEraseDown, 'INIT')
        self.state.add_transition('K', 'ELB', DoEraseEndOfLine, 'INIT')
        self.state.add_transition('r', 'ELB', DoEnableScroll, 'INIT')
        self.state.add_transition('m', 'ELB', self.do_sgr, 'INIT')
        self.state.add_transition('?', 'ELB', None, 'MODECRAP')
        self.state.add_transition_list(string.digits, 'ELB', DoStartNumber, 'NUMBER_1')
        self.state.add_transition_list(string.digits, 'NUMBER_1', DoBuildNumber, 'NUMBER_1')
        self.state.add_transition('D', 'NUMBER_1', DoBack, 'INIT')
        self.state.add_transition('B', 'NUMBER_1', DoDown, 'INIT')
        self.state.add_transition('C', 'NUMBER_1', DoForward, 'INIT')
        self.state.add_transition('A', 'NUMBER_1', DoUp, 'INIT')
        self.state.add_transition('J', 'NUMBER_1', DoErase, 'INIT')
        self.state.add_transition('K', 'NUMBER_1', DoEraseLine, 'INIT')
        self.state.add_transition('l', 'NUMBER_1', DoMode, 'INIT')
        self.state.add_transition('m', 'NUMBER_1', self.do_sgr, 'INIT')
        self.state.add_transition('q', 'NUMBER_1', self.do_decsca, 'INIT')
        self.state.add_transition_list(string.digits, 'MODECRAP', DoStartNumber, 'MODECRAP_NUM')
        self.state.add_transition_list(string.digits, 'MODECRAP_NUM', DoBuildNumber, 'MODECRAP_NUM')
        self.state.add_transition('l', 'MODECRAP_NUM', self.do_modecrap, 'INIT')
        self.state.add_transition('h', 'MODECRAP_NUM', self.do_modecrap, 'INIT')
        self.state.add_transition(';', 'NUMBER_1', None, 'SEMICOLON')
        self.state.add_transition_any('SEMICOLON', DoLog, 'INIT')
        self.state.add_transition_list(string.digits, 'SEMICOLON', DoStartNumber, 'NUMBER_2')
        self.state.add_transition_list(string.digits, 'NUMBER_2', DoBuildNumber, 'NUMBER_2')
        self.state.add_transition_any('NUMBER_2', DoLog, 'INIT')
        self.state.add_transition('H', 'NUMBER_2', DoHome, 'INIT')
        self.state.add_transition('f', 'NUMBER_2', DoHome, 'INIT')
        self.state.add_transition('r', 'NUMBER_2', DoScrollRegion, 'INIT')
        self.state.add_transition('m', 'NUMBER_2', self.do_sgr, 'INIT')
        self.state.add_transition('q', 'NUMBER_2', self.do_decsca, 'INIT')
        self.state.add_transition(';', 'NUMBER_2', None, 'SEMICOLON_X')
        self.state.add_transition_any('SEMICOLON_X', DoLog, 'INIT')
        self.state.add_transition_list(string.digits, 'SEMICOLON_X', DoStartNumber, 'NUMBER_X')
        self.state.add_transition_list(string.digits, 'NUMBER_X', DoBuildNumber, 'NUMBER_X')
        self.state.add_transition_any('NUMBER_X', DoLog, 'INIT')
        self.state.add_transition('m', 'NUMBER_X', self.do_sgr, 'INIT')
        self.state.add_transition('q', 'NUMBER_X', self.do_decsca, 'INIT')
        self.state.add_transition(';', 'NUMBER_X', None, 'SEMICOLON_X')

    def process(self, c):
        """Process a single character. Called by :meth:`write`."""
        self.state.process(c)

    def write(self, s):
        """Process text, writing it to the virtual screen while handling
        ANSI escape codes.
        """
        for c in self._decode(s):
            self.process(c)

    def write_ch(self, ch):
        """This puts a character at the current cursor position. The cursor
        position is moved forward with wrap-around, but no scrolling is done if
        the cursor hits the lower-right corner of the screen. """
        self.put(ch)

    def do_sgr(self, fsm):
        """Select Graphic Rendition, e.g. color. """
        # In a basic implementation, we'll just ignore SGR codes
        # A full implementation would handle color and text style changes
        pass

    def do_decsca(self, fsm):
        """Select character protection attribute. """
        # In a basic implementation, we'll ignore character protection
        # A full implementation would handle protected characters
        pass

    def do_modecrap(self, fsm):
        """Handler for \x1b[?<number>h and \x1b[?<number>l. If anyone
        wanted to actually use these, they'd need to add more states to the
        FSM rather than just improve or override this method. """
        # In a basic implementation, we'll ignore these mode settings
        # A full implementation would handle various terminal modes
        pass
