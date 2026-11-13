"""Home screen for the PICRYPT Kivy application."""

from kivy.app import App
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.screenmanager import Screen

from ui.android_storage import is_android
from ui.format_support import available_format_options
from ui.theme import COLORS, Panel, button, label


class MainScreen(Screen):
    """Present the primary navigation options."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        anchor = AnchorLayout(anchor_x="center", anchor_y="center", padding=[dp(18), dp(24)])
        layout = BoxLayout(orientation="vertical", spacing=dp(14), size_hint=(1, None), height=dp(520))
        layout.add_widget(label("PICRYPT", color=COLORS["accent"], font_size=dp(38), bold=True, size_hint_y=None, height=dp(58), halign="center"))
        layout.add_widget(label("SECURE MULTI-FORMAT STEGANOGRAPHY", color=COLORS["text"], font_size=dp(17), bold=True, size_hint_y=None, height=dp(30), halign="center"))
        formats = ", ".join(available_format_options())
        description = f"Encrypt confidential messages and hide them inside {formats} files. Recover your secret message using the correct password."
        layout.add_widget(label(description, color=COLORS["muted"], font_size=dp(13), size_hint_y=None, height=dp(34), halign="center"))

        android = is_android()
        actions_height = 224 if android else 194
        actions = Panel(orientation="vertical", spacing=dp(10), padding=dp(18), size_hint_y=None, height=dp(actions_height), panel_color=COLORS["surface"])
        encrypt_button = button("ENCRYPT MESSAGE", "primary", height=dp(52))
        decrypt_button = button("DECRYPT MESSAGE", "primary", height=dp(52))
        actions.add_widget(encrypt_button)
        encrypt_description = (
            f"Hide a secret message inside {formats} files"
            if android
            else "Hide a secret message inside a PNG, JPEG, PDF, or MP4 file"
        )
        decrypt_description = (
            f"Recover a secret message from {formats} files"
            if android
            else "Recover a hidden message from a PNG, JPEG, PDF, or MP4 file"
        )
        actions.add_widget(label(encrypt_description, color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(22), halign="center"))
        actions.add_widget(decrypt_button)
        actions.add_widget(label(decrypt_description, color=COLORS["muted"], font_size=dp(12), size_hint_y=None, height=dp(22), halign="center"))
        if android:
            actions.add_widget(label("JPEG and MP4 are disabled on Android until their native services are supported.", color=COLORS["warning"], font_size=dp(11), size_hint_y=None, height=dp(22), halign="center"))
        layout.add_widget(actions)

        capabilities = Panel(orientation="horizontal", spacing=dp(8), padding=dp(12), size_hint_y=None, height=dp(64), panel_color=COLORS["surface"])
        for feature in ("AES-256 ENCRYPTION", "SHA-256 KEY DERIVATION", "MULTI-FORMAT STEGANOGRAPHY"):
            capabilities.add_widget(label(feature, color=COLORS["muted"], font_size=dp(10), halign="center"))
        layout.add_widget(capabilities)
        exit_button = button("EXIT", "tertiary", height=dp(42))
        encrypt_button.bind(on_release=lambda *_: setattr(self.manager, "current", "encrypt"))
        decrypt_button.bind(on_release=lambda *_: setattr(self.manager, "current", "decrypt"))
        exit_button.bind(on_release=lambda *_: App.get_running_app().stop())
        layout.add_widget(exit_button)
        anchor.add_widget(layout)
        self.add_widget(anchor)
