"""Kivy decryption screen for PICRYPT."""

from __future__ import annotations

from pathlib import Path

from kivy.core.clipboard import Clipboard
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.image import Image
from kivy.uix.screenmanager import Screen
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner

from ui.dialogs import show_file_chooser
from ui.format_support import (
    available_format_options,
    decrypt_for_format,
    filters_for_format,
    format_file_label,
    no_file_selected_label,
    selected_file_label,
)
from ui.theme import COLORS, Panel, button, label, section_label, text_input


class DecryptScreen(Screen):
    """Select a stego image and display the recovered secret message."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.selected_image = ""
        self._build_ui()

    def _build_ui(self) -> None:
        root = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(16))
        header = BoxLayout(size_hint_y=None, height=dp(62), spacing=dp(12))
        back = button("BACK", "tertiary", size_hint_x=None, width=dp(92), height=dp(40))
        back.bind(on_release=lambda *_: self._go_home())
        header.add_widget(back)
        header.add_widget(label("PICRYPT\nDECRYPT MESSAGE", color=COLORS["text"], font_size=dp(19), bold=True))
        header.add_widget(label("Recover a hidden message from an image", color=COLORS["muted"], font_size=dp(11), halign="right"))
        root.add_widget(header)

        self.status_label = label("Ready", color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(26))
        root.add_widget(self.status_label)

        content_scroll = ScrollView(bar_width=dp(4), scroll_type=["bars", "content"])
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=[0, dp(2)], size_hint_x=None, size_hint_y=None)
        content.bind(minimum_height=content.setter("height"))

        image_card = Panel(orientation="vertical", spacing=dp(7), padding=dp(12), size_hint_y=None, height=dp(264))
        self.format_section = section_label("Stego Image")
        image_card.add_widget(self.format_section)
        self.format_spinner = Spinner(
            text="PNG",
            values=available_format_options(),
            size_hint_y=None,
            height=dp(40),
            background_normal="",
            background_color=COLORS["surface_alt"],
            color=COLORS["text"],
        )
        self.format_spinner.bind(text=self._format_changed)
        image_card.add_widget(self.format_spinner)
        self.choose_button = button("CHOOSE STEGO IMAGE", "secondary")
        self.choose_button.bind(on_release=self._choose_input)
        image_card.add_widget(self.choose_button)
        self.selected_label = label("Selected: No image selected", color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(24), shorten=True, shorten_from="right")
        image_card.add_widget(self.selected_label)
        preview_panel = Panel(orientation="vertical", size_hint_y=None, height=dp(112), panel_color=COLORS["background"])
        self.preview_placeholder = label("NO IMAGE SELECTED", color=COLORS["muted"], font_size=dp(11), halign="center")
        preview_panel.add_widget(self.preview_placeholder)
        self.preview = Image(source="", fit_mode="contain", opacity=0, size_hint_y=1)
        preview_panel.add_widget(self.preview)
        image_card.add_widget(preview_panel)
        content.add_widget(image_card)

        password_card = Panel(orientation="vertical", spacing=dp(7), padding=dp(12), size_hint_y=None, height=dp(105))
        password_card.add_widget(section_label("Password"))
        password_row = BoxLayout(size_hint_x=1, size_hint_y=None, height=dp(42), spacing=dp(8))
        self.password_input = text_input(
            hint_text="Enter your password...",
            disabled=False,
            readonly=False,
            opacity=1,
            password=True,
            multiline=False,
            size_hint_x=1,
        )
        show_password = button("SHOW", "tertiary", size_hint_x=None, width=dp(78), height=dp(42))
        show_password.bind(on_release=self._toggle_password)
        password_row.add_widget(self.password_input)
        password_row.add_widget(show_password)
        password_card.add_widget(password_row)
        content.add_widget(password_card)

        action_card = Panel(orientation="horizontal", spacing=dp(8), padding=dp(10), size_hint_y=None, height=dp(66))
        self.decrypt_button = button("DECRYPT", "primary", disabled=True)
        self.decrypt_button.bind(on_release=self._decrypt)
        self.copy_button = button("COPY MESSAGE", "secondary", disabled=True)
        self.copy_button.bind(on_release=self._copy_message)
        clear = button("CLEAR", "tertiary")
        clear.bind(on_release=lambda *_: self.reset_form())
        action_card.add_widget(self.decrypt_button)
        action_card.add_widget(self.copy_button)
        action_card.add_widget(clear)
        action_card.bind(width=lambda widget, _: self._resize_action_row(widget, action_card))
        content.add_widget(action_card)

        result_card = Panel(orientation="vertical", spacing=dp(7), padding=dp(12), size_hint_y=None, height=dp(198))
        result_card.add_widget(section_label("Recovered Message"))
        recovered_scroll = ScrollView(size_hint_x=1, size_hint_y=None, height=dp(150), bar_width=dp(4), scroll_type=["bars", "content"])
        self.recovered_input = text_input(readonly=True, multiline=True, size_hint_x=None, size_hint_y=None, height=dp(150), hint_text="Your recovered secret message will appear here.")
        recovered_scroll.add_widget(self.recovered_input)
        recovered_scroll.bind(width=lambda widget, width: setattr(self.recovered_input, "width", width))
        result_card.add_widget(recovered_scroll)
        content.add_widget(result_card)
        content_scroll.add_widget(content)
        content_scroll.bind(width=lambda widget, width: setattr(content, "width", width))
        root.add_widget(content_scroll)
        self.password_input.bind(text=lambda *_: self._refresh_button_state())
        self.add_widget(root)

    @staticmethod
    def _resize_action_row(action_card: Panel, _width: float) -> None:
        if action_card.width < dp(620):
            action_card.orientation = "vertical"
            action_card.height = dp(160)
        else:
            action_card.orientation = "horizontal"
            action_card.height = dp(66)

    def _go_home(self) -> None:
        self.manager.current = "home"

    def _format_changed(self, *_args) -> None:
        format_name = self.format_spinner.text
        self.selected_image = ""
        self.format_section.text = f"Stego {format_file_label(format_name)}"
        self.choose_button.text = f"CHOOSE STEGO {format_file_label(format_name)}"
        self.selected_label.text = f"Selected: {no_file_selected_label(format_name)}"
        self.preview.source = ""
        self.preview.opacity = 0
        self.preview_placeholder.text = selected_file_label(format_name, "NO") + " SELECTED"
        self.preview_placeholder.opacity = 1
        self._refresh_button_state()

    def _choose_input(self, *_args) -> None:
        show_file_chooser(
            self._image_selected,
            f"Choose {self.format_spinner.text} Stego File",
            filters=filters_for_format(self.format_spinner.text),
        )

    def _image_selected(self, path: Path | None) -> None:
        if path is None:
            return
        suffix = path.suffix.lower()
        if suffix == ".png":
            self.format_spinner.text = "PNG"
        elif suffix in {".jpg", ".jpeg"}:
            self.format_spinner.text = "JPEG"
        elif suffix == ".pdf":
            self.format_spinner.text = "PDF"
        elif suffix == ".mp4":
            self.format_spinner.text = "MP4"
        self.selected_image = str(path)
        self.selected_label.text = f"Selected: {path.name}"
        if self.format_spinner.text in {"PNG", "JPEG"}:
            self.preview.source = str(path)
            self.preview.reload()
            self.preview.opacity = 1
            self.preview_placeholder.opacity = 0
        else:
            self.preview.source = ""
            self.preview.opacity = 0
            self.preview_placeholder.text = f"{self.format_spinner.text} STEGO FILE SELECTED"
            self.preview_placeholder.opacity = 1
        self.status_label.text = "Ready"
        self.status_label.color = COLORS["muted"]
        self._refresh_button_state()

    def _toggle_password(self, button_widget) -> None:
        self.password_input.password = not self.password_input.password
        button_widget.text = "HIDE" if not self.password_input.password else "SHOW"

    def _refresh_button_state(self) -> None:
        self.decrypt_button.disabled = not (self.selected_image and self.password_input.text.strip())

    def _decrypt(self, *_args) -> None:
        self.status_label.text = "Processing..."
        self.status_label.color = COLORS["accent"]
        try:
            message = decrypt_for_format(self.format_spinner.text, self.selected_image, self.password_input.text)
        except (TypeError, ValueError, OSError):
            self.status_label.text = "Error: Unable to decrypt. Check the password or image."
            self.status_label.color = COLORS["danger"]
            return
        self.recovered_input.text = message
        self.copy_button.disabled = False
        self.status_label.text = "Decryption successful."
        self.status_label.color = COLORS["success"]

    def _copy_message(self, *_args) -> None:
        Clipboard.copy(self.recovered_input.text)
        self.status_label.text = "Message copied to clipboard."
        self.status_label.color = COLORS["success"]

    def reset_form(self) -> None:
        self.selected_image = ""
        self.selected_label.text = f"Selected: {no_file_selected_label(self.format_spinner.text)}"
        self.status_label.text = "Ready"
        self.status_label.color = COLORS["muted"]
        self.preview.source = ""
        self.preview.opacity = 0
        self.preview_placeholder.opacity = 1
        self.password_input.text = ""
        self.recovered_input.text = ""
        self.copy_button.disabled = True
        self._refresh_button_state()
