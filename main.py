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
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.properties import StringProperty
from kivy.uix.screenmanager import Screen, ScreenManager

import wire

KV = """
<LoginScreen>:
    canvas.before:
        Color:
            rgba: 0.03, 0.04, 0.05, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: "vertical"
        padding: dp(24)
        spacing: dp(12)
        Widget:
            size_hint_y: 0.3
        Label:
            text: "WIRE"
            font_size: "32sp"
            bold: True
            color: 0.43, 0.9, 0.78, 1
            size_hint_y: None
            height: dp(48)
        Label:
            text: "encrypted terminal chat"
            color: 0.6, 0.65, 0.7, 1
            size_hint_y: None
            height: dp(24)
        Widget:
            size_hint_y: 0.2
        TextInput:
            id: username
            hint_text: "username"
            multiline: False
            size_hint_y: None
            height: dp(48)
            write_tab: False
        TextInput:
            id: password
            hint_text: "password"
            password: True
            multiline: False
            size_hint_y: None
            height: dp(48)
            write_tab: False
        Label:
            id: status
            text: root.status
            color: 1, 0.56, 0.6, 1
            size_hint_y: None
            height: dp(24)
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(12)
            Button:
                text: "Log in"
                on_release: root.submit(username.text, password.text, signup=False)
            Button:
                text: "Sign up"
                on_release: root.submit(username.text, password.text, signup=True)
        Widget:

<ChatScreen>:
    canvas.before:
        Color:
            rgba: 0.03, 0.04, 0.05, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: "vertical"
        padding: dp(10)
        spacing: dp(6)
        Label:
            text: root.title_text
            size_hint_y: None
            height: dp(30)
            color: 0.43, 0.9, 0.78, 1
            bold: True
            text_size: self.width, None
            halign: "left"
        ScrollView:
            id: scroller
            Label:
                id: output
                text: root.log_text
                size_hint_y: None
                height: self.texture_size[1]
                text_size: self.width, None
                halign: "left"
                valign: "top"
                color: 0.9, 0.93, 0.96, 1
                padding: dp(6), dp(6)
        BoxLayout:
            size_hint_y: None
            height: dp(48)
            spacing: dp(6)
            TextInput:
                id: entry
                hint_text: "message or /command"
                multiline: False
                write_tab: False
                on_text_validate: root.send(self.text)
            Button:
                text: "Send"
                size_hint_x: 0.22
                on_release: root.send(entry.text)
"""


class LoginScreen(Screen):
    status = StringProperty("")

    def submit(self, username: str, password: str, signup: bool) -> None:
        username = username.strip()
        if not username or not password:
            self.status = "enter a username and password"
            return
        self.status = "working..."

        def worker() -> None:
            app_state: wire.Wire = App.get_running_app().wire_app
            try:
                if signup:
                    app_state.signup(username, password=password)
                else:
                    app_state.login(username, password=password)
            except Exception as exc:  # noqa: BLE001 - shown to the person, not swallowed
                Clock.schedule_once(lambda _dt: self._fail(str(exc)))
                return
            Clock.schedule_once(lambda _dt: self._succeed(username))

        threading.Thread(target=worker, daemon=True).start()

    def _fail(self, message: str) -> None:
        self.status = message

    def _succeed(self, username: str) -> None:
        self.status = ""
        App.get_running_app().show_chat(username)


class ChatScreen(Screen):
    log_text = StringProperty("")
    title_text = StringProperty("wire")

    def append(self, line: str) -> None:
        self.log_text = f"{self.log_text}\n{line}" if self.log_text else line
        scroller = self.ids.get("scroller")
        if scroller is not None:
            Clock.schedule_once(lambda _dt: setattr(scroller, "scroll_y", 0), 0)

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

    def __init__(self, append) -> None:
        self._append = append
        self._buffer = ""

    def write(self, text: str) -> int:
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            Clock.schedule_once(lambda _dt, line=line: self._append(line))
        return len(text)

    def flush(self) -> None:
        pass


class WireApp(App):
    def build(self):
        Window.clearcolor = (0.03, 0.04, 0.05, 1)
        self.wire_app = wire.Wire()
        Builder.load_string(KV)
        self.manager = ScreenManager()
        self.manager.add_widget(LoginScreen(name="login"))
        self.manager.add_widget(ChatScreen(name="chat"))
        return self.manager

    def on_start(self) -> None:
        chat = self.manager.get_screen("chat")
        wire.say = lambda text: chat.append(text)
        sys.stdout = _LineBufferedWriter(chat.append)
        sys.stderr = _LineBufferedWriter(chat.append)

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
