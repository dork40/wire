"""Wire for Android: a small Kivy shell around wire.py's existing command
API (wire.handle_input / wire.run_command), not a reimplementation of it.

Login/signup run on a background thread (scrypt and the network handshake
are both too slow for the UI thread); everything after that reuses the exact
same encrypted chat/friends/files/DND logic the desktop terminal uses, just
driven by taps instead of a real tty. wire.say() and print() are redirected
into the scrollback here instead of a terminal, matching how any other
frontend (Termux, the desktop prompt) already captures them.
"""
import sys
import traceback
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.utils import escape_markup

import wire

# Same palette as the rest of this project (the TrueNAS web console in
# wire-web.py): dark background, mint for "this is Wire / you", blue for
# other people, pink/red for errors.
MINT = "6ee7c8"
BLUE = "79a8ff"
DANGER = "ff8e9a"
MUTED = "8e9aac"
TEXT = "e8edf3"

KV = """
<RoundField@TextInput>:
    multiline: False
    write_tab: False
    font_name: "RobotoMono-Regular.ttf"
    background_normal: ""
    background_active: ""
    background_color: 0, 0, 0, 0
    foreground_color: 0.91, 0.93, 0.96, 1
    hint_text_color: 0.56, 0.6, 0.67, 1
    cursor_color: 0.43, 0.9, 0.78, 1
    selection_color: 0.43, 0.9, 0.78, 0.35
    padding: dp(14), dp(14)
    size_hint_y: None
    height: dp(52)
    font_size: "16sp"
    canvas.before:
        Color:
            rgba: 0.07, 0.1, 0.13, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(12)]
        Color:
            rgba: (0.43, 0.9, 0.78, 0.9) if self.focus else (0.14, 0.18, 0.23, 1)
        Line:
            rounded_rectangle: (self.x, self.y, self.width, self.height, dp(12))
            width: 1.2

<RoundButton@Button>:
    background_normal: ""
    background_down: ""
    background_color: 0, 0, 0, 0
    bold: True
    font_size: "16sp"
    canvas.before:
        Color:
            rgba: self.fill
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(12)]
    fill: (0.43, 0.9, 0.78, 1)
    color: 0.02, 0.07, 0.06, 1

<GhostButton@RoundButton>:
    fill: (0.1, 0.14, 0.18, 1)
    color: 0.86, 0.9, 0.94, 1

<LoginScreen>:
    canvas.before:
        Color:
            rgba: 0.02, 0.03, 0.04, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: "vertical"
        padding: dp(28)
        spacing: dp(10)
        Widget:
            size_hint_y: 0.32
        BoxLayout:
            orientation: "horizontal"
            size_hint_y: None
            height: dp(52)
            spacing: dp(10)
            pos_hint: {"center_x": 0.5}
            Widget:
            Widget:
                size_hint_x: None
                width: dp(14)
                canvas:
                    Color:
                        rgba: 0.43, 0.9, 0.78, 1
                    Ellipse:
                        pos: self.pos
                        size: self.size
            Label:
                text: "WIRE"
                font_name: "RobotoMono-Regular.ttf"
                font_size: "34sp"
                bold: True
                color: 0.93, 0.98, 0.96, 1
                size_hint_x: None
                width: self.texture_size[0]
            Widget:
        Label:
            text: "encrypted terminal chat"
            color: 0.56, 0.6, 0.67, 1
            size_hint_y: None
            height: dp(26)
        Widget:
            size_hint_y: 0.18
        RoundField:
            id: username
            hint_text: "username"
        BoxLayout:
            size_hint_y: None
            height: dp(52)
            spacing: dp(8)
            RoundField:
                id: password
                hint_text: "password"
                password: not root.show_password
            GhostButton:
                text: "show" if not root.show_password else "hide"
                size_hint_x: None
                width: dp(72)
                font_size: "13sp"
                on_release: root.show_password = not root.show_password
        Widget:
            size_hint_y: None
            height: dp(6)
        Label:
            id: status
            markup: True
            text: root.status
            color: 1, 0.56, 0.6, 1
            size_hint_y: None
            height: dp(22) if root.status else 0
            font_size: "14sp"
        BoxLayout:
            size_hint_y: None
            height: dp(52)
            spacing: dp(12)
            padding: 0, dp(6), 0, 0
            RoundButton:
                text: "Log in"
                disabled: root.busy
                opacity: 0.5 if root.busy else 1
                on_release: root.submit(username.text, password.text, signup=False)
            GhostButton:
                text: "Sign up"
                disabled: root.busy
                opacity: 0.5 if root.busy else 1
                on_release: root.submit(username.text, password.text, signup=True)
        Widget:

<ChatScreen>:
    canvas.before:
        Color:
            rgba: 0.02, 0.03, 0.04, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: "vertical"
        BoxLayout:
            size_hint_y: None
            height: dp(52)
            padding: dp(16), 0
            canvas.before:
                Color:
                    rgba: 0.05, 0.07, 0.09, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
            Widget:
                size_hint_x: None
                width: dp(10)
                canvas:
                    Color:
                        rgba: (0.43, 0.9, 0.78, 1) if root.connected else (1, 0.56, 0.6, 1)
                    Ellipse:
                        pos: self.x, self.center_y - dp(4)
                        size: dp(8), dp(8)
            Widget:
                size_hint_x: None
                width: dp(10)
            Label:
                text: root.title_text
                bold: True
                font_size: "17sp"
                color: 0.93, 0.98, 0.96, 1
                text_size: self.width, None
                halign: "left"
                valign: "middle"
        ScrollView:
            id: scroller
            bar_width: dp(4)
            bar_color: 0.43, 0.9, 0.78, 0.4
            BoxLayout:
                id: log_box
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                padding: dp(12), dp(12)
                spacing: dp(2)
        BoxLayout:
            size_hint_y: None
            height: dp(64)
            padding: dp(10), dp(8)
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: 0.05, 0.07, 0.09, 1
                Rectangle:
                    pos: self.pos
                    size: self.size
            RoundField:
                id: entry
                hint_text: "message or /command"
                height: dp(48)
                on_text_validate: root.send(self.text)
            RoundButton:
                text: "Send"
                size_hint_x: None
                width: dp(76)
                height: dp(48)
                on_release: root.send(entry.text)
"""


class LoginScreen(Screen):
    status = StringProperty("")
    busy = BooleanProperty(False)
    show_password = BooleanProperty(False)

    def submit(self, username: str, password: str, signup: bool) -> None:
        username = username.strip()
        if not username or not password:
            self.status = "enter a username and password"
            return
        self.busy = True
        self.status = "[color=8e9aacff]working...[/color]"

        def worker() -> None:
            app_state: wire.Wire = App.get_running_app().wire_app
            try:
                if signup:
                    app_state.signup(username, password=password)
                else:
                    app_state.login(username, password=password)
            except Exception as exc:  # noqa: BLE001 - shown to the person, not swallowed
                # `except ... as exc` implicitly deletes `exc` once this block
                # exits (CPython does this to avoid traceback reference
                # cycles). A lambda that reads `exc` lazily, after Clock
                # actually runs it later, raises NameError instead - capture
                # the message now, not the exception object.
                message = str(exc)
                # The UI only ever shows a short message (restore_identity
                # deliberately collapses every real cause into one generic
                # string so a failed login can't be used to tell "wrong
                # password" from "no such account"). Print the full chain so
                # `adb logcat` can actually show what happened underneath.
                traceback.print_exc()
                Clock.schedule_once(lambda _dt: self._fail(message))
                return
            Clock.schedule_once(lambda _dt: self._succeed(username))

        threading.Thread(target=worker, daemon=True).start()

    def _fail(self, message: str) -> None:
        self.busy = False
        self.status = f"[color={DANGER}ff]{escape_markup(message)}[/color]"

    def _succeed(self, username: str) -> None:
        self.busy = False
        self.status = ""
        App.get_running_app().show_chat(username)


class _LogLine(Label):
    """One scrollback entry. Long-press copies its raw (unstyled) text to
    the clipboard - phones have no mouse-drag text selection on a Label, so
    this is the chat-app-standard way to grab a message (a link, a code, a
    received password) without retyping it by hand.
    """

    LONG_PRESS_SECONDS = 0.45

    def __init__(self, raw_text: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.raw_text = raw_text
        self._press_event = None

    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            touch.grab(self)
            self._press_event = Clock.schedule_once(lambda _dt: self._copy(), self.LONG_PRESS_SECONDS)
            return True
        return super().on_touch_down(touch)

    def on_touch_move(self, touch):
        if touch.grab_current is self and self._press_event is not None:
            self._press_event.cancel()
            self._press_event = None
        return super().on_touch_move(touch)

    def on_touch_up(self, touch):
        if touch.grab_current is self:
            touch.ungrab(self)
            if self._press_event is not None:
                self._press_event.cancel()
                self._press_event = None
            return True
        return super().on_touch_up(touch)

    def _copy(self) -> None:
        self._press_event = None
        if not self.raw_text.strip():
            return
        Clipboard.copy(self.raw_text)
        # Markup [color] tags override Label.color per-run, so flashing
        # opacity (not color) is the one change that's visible on every line
        # regardless of how it's styled.
        self.opacity = 0.45
        Clock.schedule_once(lambda _dt: setattr(self, "opacity", 1), 0.15)


class ChatScreen(Screen):
    title_text = StringProperty("wire")
    connected = BooleanProperty(True)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # One resize listener for the whole log, not one per line - a
        # per-line binding would never be unbound and would pile up for as
        # long as the chat session runs.
        self.ids.log_box.bind(width=self._resize_lines)

    def _resize_lines(self, log_box, width) -> None:
        for child in log_box.children:
            child.text_size = (width - dp(24), None)

    def append(self, line: str) -> None:
        log_box = self.ids.get("log_box")
        if log_box is None:
            return
        # wire.say() sometimes passes a single call with embedded "\n"s
        # (e.g. a leading blank line before a notification); give each
        # resulting row its own widget so long-press-to-copy stays precise.
        for raw in line.split("\n"):
            log_box.add_widget(self._make_line(raw))
        scroller = self.ids.get("scroller")
        if scroller is not None:
            Clock.schedule_once(lambda _dt: setattr(scroller, "scroll_y", 0), 0)

    def _make_line(self, raw: str) -> _LogLine:
        log_box = self.ids.log_box
        widget = _LogLine(
            raw,
            text=self._style_line(raw) or " ",
            markup=True,
            font_name="RobotoMono-Regular.ttf",
            font_size="13.5sp",
            line_height=1.3,
            halign="left",
            valign="top",
            color=(0.91, 0.93, 0.96, 1),
            size_hint_y=None,
        )
        widget.text_size = (log_box.width - dp(24), None)
        widget.bind(texture_size=lambda inst, size: setattr(inst, "height", size[1]))
        return widget

    @staticmethod
    def _style_line(line: str) -> str:
        """Light markup coloring so the scrollback reads like a chat, not a
        terminal dump: your own lines in mint, "name > message" lines with
        the sender in blue, error/failure lines in red, everything else
        (connection status, /help output, etc.) muted.
        """
        stripped = line.strip()
        if not stripped:
            return line
        if stripped.startswith(">"):
            return f"[color={MINT}ff]{escape_markup(line)}[/color]"
        lowered = stripped.lower()
        if lowered.startswith(("error:", "[internal error]")) or "failed" in lowered:
            return f"[color={DANGER}ff]{escape_markup(line)}[/color]"
        name, sep, rest = stripped.partition(" > ")
        if sep and name and not name.startswith("[") and " " not in name:
            return f"[color={BLUE}ff][b]{escape_markup(name)}[/b][/color] > {escape_markup(rest)}"
        return f"[color={MUTED}ff]{escape_markup(line)}[/color]"

    def send(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        self.ids.entry.text = ""
        self.append(f"> {text}")

        def worker() -> None:
            app_state: wire.Wire = App.get_running_app().wire_app
            keep_going = wire.handle_input(app_state, text)
            if not keep_going:
                Clock.schedule_once(lambda _dt: App.get_running_app().show_login())

        threading.Thread(target=worker, daemon=True).start()


class _LineBufferedWriter:
    """Redirects print()/sys.stdout into the chat screen's scrollback.

    wire.py's command dispatcher calls plain print() for most output (the
    same thing a real terminal would capture); this is the Android
    equivalent of that capture, applied once for the whole process.
    """

    def __init__(self, append, also) -> None:
        self._append = append
        self._also = also  # the real stdout/stderr, still reaching `adb logcat`
        self._buffer = ""

    def write(self, text: str) -> int:
        try:
            self._also.write(text)
        except Exception:
            pass
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            Clock.schedule_once(lambda _dt, line=line: self._append(line))
        return len(text)

    def flush(self) -> None:
        pass


class WireApp(App):
    def build(self):
        Window.clearcolor = (0.02, 0.03, 0.04, 1)
        # Default behaviour leaves the window where it is when the on-screen
        # keyboard opens, so it covers the message field entirely and there
        # is no way to see what's being typed. "below_target" pans the
        # window up just enough to keep the focused field above the keyboard.
        Window.softinput_mode = "below_target"
        self.wire_app = wire.Wire()
        Builder.load_string(KV)
        self.manager = ScreenManager()
        self.manager.add_widget(LoginScreen(name="login"))
        self.manager.add_widget(ChatScreen(name="chat"))
        return self.manager

    def on_start(self) -> None:
        chat = self.manager.get_screen("chat")
        wire.say = lambda text: chat.append(text)
        sys.stdout = _LineBufferedWriter(chat.append, sys.stdout)
        sys.stderr = _LineBufferedWriter(chat.append, sys.stderr)

        # Without this, an uncaught exception on a background thread (login,
        # sending a message, anything in wire.py's worker threads) prints to
        # a stderr nobody on a phone can see and the thread just dies
        # silently. Route it into the same visible scrollback instead. This
        # cannot catch a native/non-Python crash (the Ed25519 segfault this
        # was added after was exactly that kind, fixed separately in
        # wire_crypto_android.py) - only genuine Python-level exceptions.
        def report_thread_exception(args: threading.ExceptHookArgs) -> None:
            text = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
            Clock.schedule_once(lambda _dt: chat.append(f"[internal error]\n{text}"))

        threading.excepthook = report_thread_exception

    def show_chat(self, username: str) -> None:
        chat = self.manager.get_screen("chat")
        chat.title_text = f"wire - {username}"
        self.manager.current = "chat"

    def show_login(self) -> None:
        self.manager.current = "login"

    def on_stop(self) -> None:
        try:
            self.wire_app.close()
        except Exception:  # noqa: BLE001 - shutting down regardless
            pass


if __name__ == "__main__":
    WireApp().run()
