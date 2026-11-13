"""Kivy encryption screen for PICRYPT."""

from __future__ import annotations

import shutil
from pathlib import Path

from kivy.metrics import dp
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.image import Image
from kivy.uix.screenmanager import Screen
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner

from ui.dialogs import show_android_save_dialog, show_file_chooser
from ui.format_support import (
    available_format_options,
    encrypt_for_format,
    extension_for_format,
    filters_for_format,
    format_file_label,
    no_file_selected_label,
    selected_file_label,
    unique_output_path,
)
from ui.android_storage import is_android
from ui.theme import COLORS, Panel, button, label, section_label, text_input


class EncryptScreen(Screen):
    """Collect encryption inputs and call the Phase 4 service."""

    selected_image = StringProperty("")
    generated_output = StringProperty("")
    download_enabled = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._build_ui()

    def _build_ui(self) -> None:
        root = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(16))
        header = BoxLayout(size_hint_y=None, height=dp(62), spacing=dp(12))
        back = button("BACK", "tertiary", size_hint_x=None, width=dp(92), height=dp(40))
        back.bind(on_release=lambda *_: self._go_home())
        header.add_widget(back)
        header.add_widget(label("PICRYPT\nENCRYPT MESSAGE", color=COLORS["text"], font_size=dp(19), bold=True))
        header.add_widget(label("Securely hide a secret message in an image", color=COLORS["muted"], font_size=dp(11), halign="right"))
        root.add_widget(header)

        self.status_label = label("Ready", color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(26))
        root.add_widget(self.status_label)

        content_scroll = ScrollView(bar_width=dp(4), scroll_type=["bars", "content"])
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=[0, dp(2)], size_hint_x=None, size_hint_y=None)
        content.bind(minimum_height=content.setter("height"))

        image_card = Panel(orientation="vertical", spacing=dp(7), padding=dp(12), size_hint_y=None, height=dp(290))
        self.format_section = section_label("Cover Image")
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
        self.choose_button = button("CHOOSE IMAGE", "secondary")
        self.choose_button.bind(on_release=self._choose_input)
        image_card.add_widget(self.choose_button)
        self.selected_label = label("Selected: No image selected", color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(24), shorten=True, shorten_from="right")
        image_card.add_widget(self.selected_label)
        preview_panel = Panel(orientation="vertical", size_hint_y=None, height=dp(140), panel_color=COLORS["background"])
        self.preview_placeholder = label("NO IMAGE SELECTED", color=COLORS["muted"], font_size=dp(11), halign="center")
        preview_panel.add_widget(self.preview_placeholder)
        self.preview = Image(source="", fit_mode="contain", opacity=0, size_hint_y=1)
        preview_panel.add_widget(self.preview)
        image_card.add_widget(preview_panel)
        content.add_widget(image_card)

        message_card = Panel(orientation="vertical", spacing=dp(7), padding=dp(12), size_hint_y=None, height=dp(190))
        message_card.add_widget(section_label("Secret Message"))
        self.message_input = text_input(
            hint_text="Enter your secret message...",
            disabled=False,
            readonly=False,
            multiline=True,
            opacity=1,
            size_hint_x=1,
            size_hint_y=None,
            height=dp(140),
        )
        message_card.add_widget(self.message_input)
        content.add_widget(message_card)

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

        action_card = Panel(orientation="vertical", spacing=dp(8), padding=dp(10), size_hint_y=None, height=dp(108))
        actions = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(8))
        self.encrypt_button = button("ENCRYPT", "primary", disabled=True)
        self.encrypt_button.bind(on_release=self._encrypt)
        self.download_button = button("DOWNLOAD / SAVE IMAGE", "primary", disabled=True)
        self.download_button.bind(on_release=self._choose_save_destination)
        another = button("ENCRYPT ANOTHER", "secondary")
        another.bind(on_release=lambda *_: self.reset_form())
        actions.add_widget(self.encrypt_button)
        actions.add_widget(self.download_button)
        actions.add_widget(another)
        actions.bind(width=lambda widget, _: self._resize_action_row(widget, action_card))
        action_card.add_widget(actions)
        self.output_label = label("Output: None", color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(26), shorten=True, shorten_from="right")
        action_card.add_widget(self.output_label)
        content.add_widget(action_card)

        content_scroll.add_widget(content)
        content_scroll.bind(width=lambda widget, width: setattr(content, "width", width))
        root.add_widget(content_scroll)
        self.message_input.bind(text=lambda *_: self._refresh_button_state())
        self.password_input.bind(text=lambda *_: self._refresh_button_state())
        self.add_widget(root)

    @staticmethod
    def _resize_action_row(actions: BoxLayout, action_card: Panel) -> None:
        if actions.width < dp(620):
            actions.orientation = "vertical"
            actions.height = dp(152)
            action_card.height = dp(212)
        else:
            actions.orientation = "horizontal"
            actions.height = dp(48)
            action_card.height = dp(108)

    def _go_home(self) -> None:
        self.manager.current = "home"

    def _format_changed(self, *_args) -> None:
        format_name = self.format_spinner.text
        self.selected_image = ""
        self.format_section.text = f"Cover {format_file_label(format_name)}"
        self.choose_button.text = f"CHOOSE {format_file_label(format_name)}"
        self.selected_label.text = f"Selected: {no_file_selected_label(format_name)}"
        self.download_button.text = f"DOWNLOAD / SAVE {format_file_label(format_name)}"
        self.preview.source = ""
        self.preview.opacity = 0
        self.preview_placeholder.text = selected_file_label(format_name, "NO") + " SELECTED"
        self.preview_placeholder.opacity = 1
        self._refresh_button_state()

    def _choose_input(self, *_args) -> None:
        show_file_chooser(
            self._image_selected,
            f"Choose {self.format_spinner.text} Carrier",
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
            self.preview_placeholder.text = f"{self.format_spinner.text} CARRIER SELECTED"
            self.preview_placeholder.opacity = 1
        self.status_label.text = "Ready"
        self.status_label.color = COLORS["muted"]
        self._refresh_button_state()

    def _toggle_password(self, button_widget) -> None:
        self.password_input.password = not self.password_input.password
        button_widget.text = "HIDE" if not self.password_input.password else "SHOW"

    def _refresh_button_state(self) -> None:
        self.encrypt_button.disabled = not (
            self.selected_image and self.message_input.text.strip() and self.password_input.text.strip()
        )

    def _encrypt(self, *_args) -> None:
        self.status_label.text = "Processing..."
        self.status_label.color = COLORS["accent"]
        try:
            output = encrypt_for_format(
                self.format_spinner.text,
                self.selected_image,
                self.message_input.text,
                self.password_input.text,
                unique_output_path(self.selected_image, self.format_spinner.text),
            )
        except (TypeError, ValueError, OSError) as exc:
            self.status_label.text = f"Error: {self._friendly_error(str(exc))}"
            self.status_label.color = COLORS["danger"]
            return
        self.generated_output = str(output)
        self.output_label.text = f"Generated: {output.name}"
        if self.format_spinner.text in {"PNG", "JPEG"}:
            self.preview.source = str(output)
            self.preview.reload()
            self.preview.opacity = 1
            self.preview_placeholder.opacity = 0
        else:
            self.preview.source = ""
            self.preview.opacity = 0
            self.preview_placeholder.text = f"{self.format_spinner.text} OUTPUT READY"
            self.preview_placeholder.opacity = 1
        self.download_button.disabled = False
        self.status_label.text = "Encryption successful."
        self.status_label.color = COLORS["success"]

    def _choose_save_destination(self, *_args) -> None:
        extension = extension_for_format(self.format_spinner.text)
        if is_android():
            show_android_save_dialog(
                Path(self.generated_output),
                self._save_generated_image,
                f"PICRYPT_stego{extension}",
                extension,
            )
            return
        show_file_chooser(
            self._save_generated_image,
            f"Save Stego {self.format_spinner.text}",
            save=True,
            default_name=f"PICRYPT_stego{extension}",
            filters=filters_for_format(self.format_spinner.text),
            default_extension=extension,
        )

    def _save_generated_image(self, destination: Path | None) -> None:
        if destination is None or not self.generated_output:
            self.status_label.text = "Save cancelled."
            return
        if is_android():
            self.status_label.text = "Stego file exported successfully."
            self.status_label.color = COLORS["success"]
            return
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.generated_output, destination)
        except OSError:
            self.status_label.text = "Error: Unable to save the stego image."
            self.status_label.color = COLORS["danger"]
            return
        self.status_label.text = "Stego image saved successfully."
        self.status_label.color = COLORS["success"]

    def reset_form(self) -> None:
        self.selected_image = ""
        self.generated_output = ""
        self.selected_label.text = f"Selected: {no_file_selected_label(self.format_spinner.text)}"
        self.output_label.text = "Output: None"
        self.status_label.text = "Ready"
        self.status_label.color = COLORS["muted"]
        self.preview.source = ""
        self.preview.opacity = 0
        self.preview_placeholder.text = f"NO {self.format_spinner.text} SELECTED"
        self.preview_placeholder.opacity = 1
        self.message_input.text = ""
        self.password_input.text = ""
        self.download_button.disabled = True
        self._refresh_button_state()

    @staticmethod
    def _friendly_error(message: str) -> str:
        replacements = {
            "Message cannot be empty.": "Please enter a secret message.",
            "Password cannot be empty.": "Please enter a password.",
            "Please select an image.": "Please select an image.",
            "Message is too large for this image.": "Message is too large for this image.",
        }
        return replacements.get(message, message)
