"""Wire for Android: a small Kivy shell around wire.py's existing command
API (wire.handle_input / wire.run_command), not a reimplementation of it.

Login/signup run on a background thread (scrypt and the network handshake
are both too slow for the UI thread); everything after that reuses the exact
same encrypted chat/friends/files/DND logic the desktop terminal uses, just
driven by taps instead of a real tty. wire.say() and print() are redirected
into the scrollback here instead of a terminal, matching how any other
frontend (Termux, the desktop prompt) already captures them.
"""
import json
import os
import shutil
import sys
import time
import traceback
import threading
import uuid
from pathlib import Path

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.factory import Factory
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.utils import escape_markup, platform

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

<DangerButton@RoundButton>:
    fill: (0.3, 0.1, 0.13, 1)
    color: 1, 0.72, 0.76, 1

<SmallButton@GhostButton>:
    size_hint: None, None
    width: dp(84)
    height: dp(38)
    font_size: "14sp"
    pos_hint: {"center_y": 0.5}

<Card@BoxLayout>:
    orientation: "vertical"
    size_hint_y: None
    height: self.minimum_height
    padding: dp(14)
    spacing: dp(10)
    canvas.before:
        Color:
            rgba: 0.06, 0.08, 0.11, 1
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<SectionLabel@Label>:
    size_hint_y: None
    height: dp(28)
    color: 0.56, 0.6, 0.67, 1
    font_size: "13sp"
    bold: True
    text_size: self.width, None
    halign: "left"

<TopBar@BoxLayout>:
    size_hint_y: None
    height: dp(56)
    padding: dp(12), 0
    spacing: dp(10)
    canvas.before:
        Color:
            rgba: 0.05, 0.07, 0.09, 1
        Rectangle:
            pos: self.pos
            size: self.size

<StatusLine@Label>:
    size_hint_y: None
    height: dp(34) if self.text else 0
    opacity: 1 if self.text else 0
    font_size: "13sp"
    text_size: self.width - dp(24), None
    halign: "left"
    shorten: True
    shorten_from: "right"
    markup: True

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
                shorten: True
            SmallButton:
                text: "Groups"
                on_release: app.show_groups()
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
            GhostButton:
                text: "+"
                font_size: "24sp"
                size_hint: None, None
                size: dp(48), dp(48)
                on_release: app.pick_attachment()
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

<GroupsScreen>:
    canvas.before:
        Color:
            rgba: 0.02, 0.03, 0.04, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: "vertical"
        TopBar:
            SmallButton:
                text: "Back"
                on_release: app.show_chat()
            Label:
                text: "Groups"
                bold: True
                font_size: "18sp"
                color: 0.93, 0.98, 0.96, 1
                text_size: self.width, None
                halign: "left"
            SmallButton:
                text: "Refresh"
                on_release: app.run_line("/group list", echo=False)
        ScrollView:
            BoxLayout:
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                padding: dp(14)
                spacing: dp(12)
                BoxLayout:
                    id: list_box
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    spacing: dp(12)
                SectionLabel:
                    text: "NEW GROUP"
                Card:
                    RoundField:
                        id: new_name
                        hint_text: "group name (3-32 letters, numbers, - or _)"
                    RoundField:
                        id: new_members
                        hint_text: "people to invite (space separated, optional)"
                    RoundButton:
                        text: "Create group"
                        size_hint_y: None
                        height: dp(48)
                        on_release: root.create(new_name.text, new_members.text)
        StatusLine:
            text: app.last_line_markup

<GroupScreen>:
    canvas.before:
        Color:
            rgba: 0.02, 0.03, 0.04, 1
        Rectangle:
            pos: self.pos
            size: self.size
    BoxLayout:
        orientation: "vertical"
        TopBar:
            SmallButton:
                text: "Back"
                on_release: app.show_groups()
            Label:
                text: root.group_name
                bold: True
                font_size: "18sp"
                color: 0.93, 0.98, 0.96, 1
                text_size: self.width, None
                halign: "left"
                shorten: True
            Label:
                text: root.my_role
                size_hint_x: None
                width: dp(70)
                color: 0.43, 0.9, 0.78, 1
                font_size: "13sp"
        ScrollView:
            BoxLayout:
                orientation: "vertical"
                size_hint_y: None
                height: self.minimum_height
                padding: dp(14)
                spacing: dp(12)
                BoxLayout:
                    size_hint_y: None
                    height: dp(48)
                    spacing: dp(10)
                    RoundButton:
                        text: "Open chat"
                        on_release: root.open_chat()
                    GhostButton:
                        text: "Pinned"
                        on_release: root.show_pins()
                SectionLabel:
                    text: "INVITE SOMEONE" if root.is_admin else "ONLY ADMINS CAN INVITE"
                BoxLayout:
                    size_hint_y: None
                    height: dp(52)
                    spacing: dp(8)
                    disabled: not root.is_admin
                    opacity: 1 if root.is_admin else 0.4
                    RoundField:
                        id: invite_name
                        hint_text: "username"
                    RoundButton:
                        text: "Invite"
                        size_hint_x: None
                        width: dp(90)
                        on_release: root.invite(invite_name.text)
                SectionLabel:
                    text: root.members_heading
                BoxLayout:
                    id: members_box
                    orientation: "vertical"
                    size_hint_y: None
                    height: self.minimum_height
                    spacing: dp(8)
                Widget:
                    size_hint_y: None
                    height: dp(8)
                DangerButton:
                    id: leave_button
                    text: "Leave group"
                    size_hint_y: None
                    height: dp(48)
                    on_release: root.leave(self)
        StatusLine:
            text: app.last_line_markup
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
            if raw.strip():
                App.get_running_app().set_last_line(raw, self._style_line(raw))
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
        if not text.strip():
            return
        self.ids.entry.text = ""
        self.run_line(text)

    def run_line(self, text: str, echo: bool = True) -> None:
        """Run one line exactly as if it had been typed, without touching
        whatever is in the message box (group buttons use this too)."""
        text = text.strip()
        if not text:
            return
        if echo:
            self.append(f"> {text}")

        def worker() -> None:
            app_state: wire.Wire = App.get_running_app().wire_app
            keep_going = wire.handle_input(app_state, text)
            if not keep_going:
                Clock.schedule_once(lambda _dt: App.get_running_app().show_login())

        threading.Thread(target=worker, daemon=True).start()


def _confirm_then(button, action, prompt: str = "Tap again") -> None:
    """Two-tap confirmation for destructive buttons (leave, remove) - a stray
    thumb on a phone shouldn't kick someone out of a group."""
    if getattr(button, "_armed", False):
        button._armed = False
        button.text = button._original_text
        action()
        return
    button._armed = True
    button._original_text = button.text
    button.text = prompt

    def disarm(_dt) -> None:
        if getattr(button, "_armed", False):
            button._armed = False
            button.text = button._original_text

    Clock.schedule_once(disarm, 3)


def _wire_snapshot(state: "wire.Wire") -> tuple[list[dict], list[str]] | None:
    """Copy group state owned by wire.py's network thread. A dict changing
    size mid-copy just means "try again next tick", not an error."""
    try:
        groups = [dict(group) for group in list(state.groups.values())]
        invites = sorted(name for key, name in list(state.group_invites.items()) if key not in state.groups)
    except RuntimeError:
        return None
    return groups, invites


def _my_role(state: "wire.Wire", group: dict) -> str:
    me = (state.name or "").lower()
    for member in group.get("members", []):
        if isinstance(member, dict) and str(member.get("name", "")).lower() == me:
            return str(member.get("role", "member"))
    return "member"


def _text(text: str, color=(0.91, 0.93, 0.96, 1), bold: bool = False, size: str = "15sp") -> Label:
    label = Label(text=text, color=color, bold=bold, font_size=size, halign="left", valign="middle", shorten=True)
    label.bind(size=lambda inst, value: setattr(inst, "text_size", value))
    return label


class GroupsScreen(Screen):
    def on_pre_enter(self, *_args) -> None:
        self._snapshot = None
        self._poll = Clock.schedule_interval(lambda _dt: self._rebuild(), 1)
        self._rebuild()
        App.get_running_app().run_line("/group list", echo=False)

    def on_leave(self, *_args) -> None:
        self._poll.cancel()

    def create(self, name: str, members: str) -> None:
        name = name.strip()
        if not name:
            App.get_running_app().set_last_line("error: enter a group name first")
            return
        App.get_running_app().run_line(f"/group create {name} {' '.join(members.split())}".strip())
        self.ids.new_name.text = ""
        self.ids.new_members.text = ""

    def _rebuild(self) -> None:
        app = App.get_running_app()
        snapshot = _wire_snapshot(app.wire_app)
        if snapshot is None:
            return
        key = json.dumps(snapshot, sort_keys=True, default=str)
        if key == self._snapshot:
            return
        self._snapshot = key
        groups, invites = snapshot
        box = self.ids.list_box
        box.clear_widgets()

        if invites:
            box.add_widget(Factory.SectionLabel(text="INVITES"))
            for name in invites:
                row = BoxLayout(size_hint_y=None, height=dp(52), spacing=dp(10))
                row.add_widget(_text(f"{name}", bold=True))
                join = Factory.RoundButton(text="Join", size_hint_x=None, width=dp(90))
                join.bind(on_release=lambda _b, name=name: app.run_line(f"/group accept {name}"))
                row.add_widget(join)
                card = Factory.Card()
                card.add_widget(row)
                box.add_widget(card)

        box.add_widget(Factory.SectionLabel(text=f"YOUR GROUPS ({len(groups)})"))
        if not groups:
            box.add_widget(_text("No groups yet - create one below.", color=(0.56, 0.6, 0.67, 1), size="14sp"))
        for group in sorted(groups, key=lambda item: str(item.get("name", "")).lower()):
            name = str(group.get("name", "?"))
            members = [item for item in group.get("members", []) if isinstance(item, dict)]
            online = sum(1 for item in members if item.get("online"))
            card = Factory.Card()
            header = BoxLayout(size_hint_y=None, height=dp(26))
            header.add_widget(_text(name, bold=True, size="16sp"))
            header.add_widget(_text(f"{online}/{len(members)} online · {_my_role(app.wire_app, group)}",
                                    color=(0.56, 0.6, 0.67, 1), size="13sp"))
            card.add_widget(header)
            buttons = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(10))
            open_button = Factory.RoundButton(text="Open chat")
            open_button.bind(on_release=lambda _b, name=name: app.open_group_chat(name))
            manage = Factory.GhostButton(text="Members & settings")
            manage.bind(on_release=lambda _b, name=name: app.show_group(name))
            buttons.add_widget(open_button)
            buttons.add_widget(manage)
            card.add_widget(buttons)
            box.add_widget(card)


class GroupScreen(Screen):
    group_name = StringProperty("")
    my_role = StringProperty("")
    is_admin = BooleanProperty(False)
    members_heading = StringProperty("MEMBERS")

    def on_pre_enter(self, *_args) -> None:
        self._snapshot = None
        self._misses = 0
        self.ids.invite_name.text = ""
        self._poll = Clock.schedule_interval(lambda _dt: self._rebuild(), 1)
        self._rebuild()

    def on_leave(self, *_args) -> None:
        self._poll.cancel()

    def open_chat(self) -> None:
        App.get_running_app().open_group_chat(self.group_name)

    def show_pins(self) -> None:
        app = App.get_running_app()
        app.run_line(f"/group pins {self.group_name}")
        app.show_chat()

    def invite(self, username: str) -> None:
        username = username.strip()
        if not username.isalnum():
            App.get_running_app().set_last_line("error: usernames are letters and numbers only")
            return
        App.get_running_app().run_line(f"/group invite {self.group_name} {username}")
        self.ids.invite_name.text = ""

    def leave(self, button) -> None:
        _confirm_then(button, lambda: App.get_running_app().run_line(f"/group leave {self.group_name}"),
                      "Tap again to leave")

    def _rebuild(self) -> None:
        app = App.get_running_app()
        snapshot = _wire_snapshot(app.wire_app)
        if snapshot is None:
            return
        group = next((item for item in snapshot[0] if str(item.get("name", "")).lower() == self.group_name.lower()), None)
        if group is None:
            # "/group list" empties the list until the server's reply refills
            # it, so one missing tick may just be a refresh in flight. Missing
            # twice in a row means we left / were removed.
            self._misses = getattr(self, "_misses", 0) + 1
            if self._misses >= 2:
                self._poll.cancel()
                Clock.schedule_once(lambda _dt: app.show_groups())
            return
        self._misses = 0
        key = json.dumps(group, sort_keys=True, default=str)
        if key == self._snapshot:
            return
        self._snapshot = key
        role = _my_role(app.wire_app, group)
        self.my_role = role
        self.is_admin = role in ("owner", "admin")
        members = [item for item in group.get("members", []) if isinstance(item, dict)]
        self.members_heading = f"MEMBERS ({len(members)})"
        me = (app.wire_app.name or "").lower()
        order = {"owner": 0, "admin": 1, "member": 2}
        box = self.ids.members_box
        box.clear_widgets()
        for member in sorted(members, key=lambda item: (order.get(item.get("role"), 3), str(item.get("name", "")).lower())):
            name = str(member.get("name", "?"))
            member_role = str(member.get("role", "member"))
            is_me = name.lower() == me
            card = Factory.Card()
            top = BoxLayout(size_hint_y=None, height=dp(26))
            top.add_widget(_text(f"{name}{' (you)' if is_me else ''}", bold=True))
            # Plain words, not a status dot: Kivy's bundled fonts have no
            # circle glyphs and render them as empty boxes.
            online = bool(member.get("online"))
            top.add_widget(_text(f"{'online' if online else 'offline'} · {member_role}",
                                 color=(0.43, 0.9, 0.78, 1) if online else (0.56, 0.6, 0.67, 1), size="13sp"))
            card.add_widget(top)
            actions = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(8))
            if role == "owner" and not is_me:
                promote = member_role != "admin"
                toggle = Factory.GhostButton(text="Make admin" if promote else "Remove admin", font_size="14sp")
                toggle.bind(on_release=lambda _b, name=name, promote=promote: app.run_line(
                    f"/group {'admin' if promote else 'member'} {self.group_name} {name}"))
                actions.add_widget(toggle)
            if self.is_admin and not is_me and member_role != "owner":
                remove = Factory.DangerButton(text="Remove", font_size="14sp")
                remove.bind(on_release=lambda button, name=name: _confirm_then(
                    button, lambda: app.run_line(f"/group kick {self.group_name} {name}")))
                actions.add_widget(remove)
            if actions.children:
                card.add_widget(actions)
            box.add_widget(card)


ANDROID_PICK_REQUEST = 4127


def _android_pick_file(on_ready, on_error) -> None:
    """Open Android's own file picker (Storage Access Framework).

    Needs no storage permission: the person picks one file, Android grants
    access to just that file, and it's copied into the app's cache so
    wire.py's normal /send can read it like any other path.
    """
    from android import activity  # provided by python-for-android
    from jnius import autoclass

    Intent = autoclass("android.content.Intent")
    OpenableColumns = autoclass("android.provider.OpenableColumns")
    python_activity = autoclass("org.kivy.android.PythonActivity").mActivity

    def on_result(request_code, result_code, data) -> None:
        if request_code != ANDROID_PICK_REQUEST:
            return
        activity.unbind(on_activity_result=on_result)
        try:
            if result_code != -1 or data is None or data.getData() is None:  # -1 is Activity.RESULT_OK
                return
            uri = data.getData()
            resolver = python_activity.getContentResolver()
            name = "attachment"
            cursor = resolver.query(uri, None, None, None, None)
            if cursor is not None:
                try:
                    if cursor.moveToFirst():
                        index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if index >= 0 and cursor.getString(index):
                            name = cursor.getString(index)
                finally:
                    cursor.close()
            # Take ownership of a raw file descriptor here, on the thread
            # Android called us on, so the (possibly huge) copy below can run
            # on a plain Python thread that never touches Java - a Python
            # thread that calls into Java must detach before exiting or
            # Android kills the whole app.
            descriptor = resolver.openFileDescriptor(uri, "r")
            fd = descriptor.detachFd()
            descriptor.close()
            cache = Path(python_activity.getCacheDir().getAbsolutePath()) / "outgoing"
        except Exception as exc:  # noqa: BLE001 - shown to the person
            message = f"error: couldn't open that file ({exc}). Try saving it to your phone first."
            Clock.schedule_once(lambda _dt: on_error(message))
            return
        threading.Thread(target=_copy_descriptor, args=(fd, cache, name, on_ready, on_error), daemon=True).start()

    intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
    intent.addCategory(Intent.CATEGORY_OPENABLE)
    intent.setType("*/*")
    activity.bind(on_activity_result=on_result)
    python_activity.startActivityForResult(intent, ANDROID_PICK_REQUEST)


def _copy_descriptor(fd: int, cache: Path, name: str, on_ready, on_error) -> None:
    try:
        target_dir = cache / uuid.uuid4().hex
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / wire.safe_filename(name, "attachment")
        with os.fdopen(fd, "rb") as source, target.open("wb") as destination:
            shutil.copyfileobj(source, destination, 1024 * 1024)
    except Exception as exc:  # noqa: BLE001 - shown to the person
        message = f"error: couldn't copy that file ({exc})"
        Clock.schedule_once(lambda _dt: on_error(message))
        return
    Clock.schedule_once(lambda _dt: on_ready(str(target)))


def _clear_old_attachment_copies(cache: Path, max_age_seconds: int = 2 * 24 * 3600) -> None:
    """Picked files are copied into the cache and must outlive the send
    (the peer may accept minutes later), so tidy up on the next start."""
    try:
        for item in cache.iterdir():
            if time.time() - item.stat().st_mtime > max_age_seconds:
                shutil.rmtree(item, ignore_errors=True)
    except OSError:
        pass


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
    last_line_markup = StringProperty("")

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
        self.manager.add_widget(GroupsScreen(name="groups"))
        self.manager.add_widget(GroupScreen(name="group"))
        return self.manager

    def on_start(self) -> None:
        chat = self.manager.get_screen("chat")
        # wire.say() is called from wire.py's network threads, and the
        # scrollback creates a widget per line - Kivy only allows that on its
        # main thread, so hand every line over to it (Clock keeps the order).
        wire.say = lambda text: Clock.schedule_once(lambda _dt: chat.append(text))
        if platform == "android":
            try:
                from jnius import autoclass
                cache = autoclass("org.kivy.android.PythonActivity").mActivity.getCacheDir().getAbsolutePath()
                _clear_old_attachment_copies(Path(cache) / "outgoing")
            except Exception:  # noqa: BLE001 - housekeeping only
                pass
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

    def show_chat(self, username: str | None = None) -> None:
        if username:
            self.manager.get_screen("chat").title_text = f"wire - {username}"
        self.manager.current = "chat"

    def show_login(self) -> None:
        self.manager.current = "login"

    def show_groups(self) -> None:
        self.manager.current = "groups"

    def show_group(self, name: str) -> None:
        self.manager.get_screen("group").group_name = name
        self.manager.current = "group"

    def open_group_chat(self, name: str) -> None:
        self.run_line(f"/group open {name}")
        self.show_chat()

    def run_line(self, text: str, echo: bool = True) -> None:
        self.manager.get_screen("chat").run_line(text, echo=echo)

    def set_last_line(self, raw: str, markup: str | None = None) -> None:
        """The newest scrollback line, mirrored onto the group screens so
        replies like "that person does not allow group invites" are seen
        without switching back to the chat."""
        if markup is None:
            markup = ChatScreen._style_line(raw)
        self.last_line_markup = markup

    def pick_attachment(self) -> None:
        if platform == "android":
            _android_pick_file(self._send_picked_file, self.set_last_line_and_log)
            return
        chooser = FileChooserListView(path=str(Path.home()))
        layout = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(8))
        layout.add_widget(chooser)
        buttons = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        popup = Popup(title="Send a file", content=layout, size_hint=(0.92, 0.9))
        cancel = Factory.GhostButton(text="Cancel")
        cancel.bind(on_release=lambda _b: popup.dismiss())
        send = Factory.RoundButton(text="Send")

        def choose(_button) -> None:
            if chooser.selection:
                popup.dismiss()
                self._send_picked_file(chooser.selection[0])

        send.bind(on_release=choose)
        buttons.add_widget(cancel)
        buttons.add_widget(send)
        layout.add_widget(buttons)
        popup.open()

    def _send_picked_file(self, path: str) -> None:
        self.run_line(f'/send "{path}"')

    def set_last_line_and_log(self, message: str) -> None:
        self.manager.get_screen("chat").append(message)

    def on_stop(self) -> None:
        try:
            self.wire_app.close()
        except Exception:  # noqa: BLE001 - shutting down regardless
            pass


if __name__ == "__main__":
    WireApp().run()
