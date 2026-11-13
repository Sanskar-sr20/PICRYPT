"""Reusable Kivy file chooser dialogs for PICRYPT."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.textinput import TextInput
from kivy.utils import platform

from ui.theme import COLORS, button, label, text_input
from ui.android_storage import create_document, open_document

IMAGE_FILTERS = ["*.png", "*.PNG", "*.jpg", "*.JPG", "*.jpeg", "*.JPEG"]


def show_file_chooser(
    callback: Callable[[Path | None], None],
    title: str,
    save: bool = False,
    default_name: str = "",
    filters: list[str] | None = None,
    default_extension: str = ".png",
) -> Popup | None:
    """Show a format-aware file chooser and invoke callback with its path."""
    if platform == "android":
        selected_filters = filters or IMAGE_FILTERS
        if save:
            raise ValueError("Android save dialogs require a generated source file.")
        open_document(selected_filters, callback)
        return None

    chooser = FileChooserListView(
        path=str(Path.home()),
        filters=filters or IMAGE_FILTERS,
        multiselect=False,
        dirselect=save,
    )
    content = BoxLayout(orientation="vertical", spacing=dp(8), padding=dp(10))
    filename = text_input(
        text=default_name,
        hint_text="Filename (PNG preferred)" if save else "",
        size_hint_y=None,
        height=dp(42),
        multiline=False,
    )
    actions = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
    popup = Popup(title=title, content=content, size_hint=(0.92, 0.88), auto_dismiss=False,
                  background_color=COLORS["surface"], title_color=COLORS["text"])

    def cancel(*_args) -> None:
        popup.dismiss()
        callback(None)

    def accept(*_args) -> None:
        if save:
            folder = Path(chooser.path)
            selected = chooser.selection[0] if chooser.selection else ""
            if selected and Path(selected).is_dir():
                folder = Path(selected)
            name = filename.text.strip() or default_name or "PICRYPT_stego.png"
            destination = Path(name)
            if not destination.suffix:
                destination = destination.with_suffix(default_extension)
            if not destination.is_absolute():
                destination = folder / destination
            popup.dismiss()
            callback(destination)
            return

        if not chooser.selection:
            return
        selected = Path(chooser.selection[0])
        if not selected.is_file():
            return
        popup.dismiss()
        callback(selected)

    if save:
        content.add_widget(label("Choose a destination for the generated stego image.", color=COLORS["muted"], size_hint_y=None, height=dp(28)))
        content.add_widget(chooser)
        content.add_widget(filename)
    else:
        content.add_widget(chooser)

    cancel_button = button("CANCEL", "tertiary")
    accept_button = button("SAVE" if save else "CHOOSE", "primary")
    cancel_button.bind(on_release=cancel)
    accept_button.bind(on_release=accept)
    actions.add_widget(cancel_button)
    actions.add_widget(accept_button)
    content.add_widget(actions)
    popup.open()
    return popup


def show_android_save_dialog(
    source: Path,
    callback: Callable[[Path | None], None],
    display_name: str,
    extension: str,
) -> None:
    """Export a generated file through Android's document picker."""
    mime_type = "application/pdf" if extension.lower() == ".pdf" else "image/png"
    create_document(source, display_name, mime_type, callback)
