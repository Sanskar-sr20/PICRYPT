"""Shared visual styling for the PICRYPT Kivy interface."""

from __future__ import annotations

from kivy.graphics import Color, RoundedRectangle
from kivy.metrics import dp
from kivy.properties import ListProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput

COLORS = {
    "background": (0.035, 0.055, 0.075, 1),
    "surface": (0.065, 0.095, 0.125, 1),
    "surface_alt": (0.085, 0.12, 0.155, 1),
    "border": (0.14, 0.22, 0.28, 1),
    "accent": (0.22, 0.68, 0.86, 1),
    "accent_dark": (0.10, 0.34, 0.46, 1),
    "text": (0.91, 0.95, 0.97, 1),
    "muted": (0.55, 0.64, 0.69, 1),
    "success": (0.28, 0.82, 0.55, 1),
    "warning": (1.0, 0.65, 0.24, 1),
    "danger": (1.0, 0.36, 0.35, 1),
}


class Panel(BoxLayout):
    """Dark rounded panel used to group related controls."""

    panel_color = ListProperty(COLORS["surface"])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            self._panel_color = Color(rgba=self.panel_color)
            self._panel_shape = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])
        self.bind(pos=self._update_panel, size=self._update_panel, panel_color=self._update_panel)

    def _update_panel(self, *_args) -> None:
        self._panel_color.rgba = self.panel_color
        self._panel_shape.pos = self.pos
        self._panel_shape.size = self.size


def _rounded_background(widget, color, radius: float = 8) -> None:
    with widget.canvas.before:
        fill = Color(rgba=color)
        shape = RoundedRectangle(pos=widget.pos, size=widget.size, radius=[dp(radius)])

    def update(*_args) -> None:
        shape.pos = widget.pos
        shape.size = widget.size
        if widget.disabled:
            fill.rgba = (color[0] * 0.45, color[1] * 0.45, color[2] * 0.45, color[3])
        elif getattr(widget, "state", "normal") == "down":
            fill.rgba = (color[0] * 0.82, color[1] * 0.82, color[2] * 0.82, color[3])
        else:
            fill.rgba = color

    bindings = {"pos": update, "size": update, "disabled": update}
    if "state" in widget.properties():
        bindings["state"] = update
    widget.bind(**bindings)
    update()


def label(text: str = "", **kwargs) -> Label:
    defaults = {
        "color": COLORS["text"],
        "font_size": dp(14),
        "halign": "left",
        "valign": "middle",
    }
    defaults.update(kwargs)
    result = Label(text=text, **defaults)
    result.bind(size=lambda widget, _: setattr(widget, "text_size", widget.size))
    return result


def section_label(text: str) -> Label:
    return label(text.upper(), color=COLORS["accent"], font_size=dp(12), bold=True, size_hint_y=None, height=dp(24))


def button(text: str, level: str = "secondary", **kwargs) -> Button:
    palette = {
        "primary": (COLORS["accent_dark"], COLORS["text"]),
        "secondary": (COLORS["surface_alt"], COLORS["text"]),
        "tertiary": (COLORS["background"], COLORS["muted"]),
    }
    background, foreground = palette[level]
    defaults = {
        "background_normal": "",
        "background_down": "",
        "background_color": (0, 0, 0, 0),
        "color": foreground,
        "font_size": dp(13),
        "bold": level == "primary",
        "size_hint_y": None,
        "height": dp(44),
    }
    defaults.update(kwargs)
    result = Button(text=text, **defaults)
    _rounded_background(result, background)
    return result


def text_input(**kwargs) -> TextInput:
    defaults = {
        "background_normal": "",
        "background_active": "",
        "background_color": COLORS["surface_alt"],
        "foreground_color": COLORS["text"],
        "hint_text_color": COLORS["muted"],
        "cursor_color": COLORS["accent"],
        "selection_color": (COLORS["accent"][0], COLORS["accent"][1], COLORS["accent"][2], 0.35),
        "padding": [dp(12), dp(10)],
        "font_size": dp(14),
    }
    defaults.update(kwargs)
    return TextInput(**defaults)
