"""PICRYPT Kivy application entry point."""

from kivy.app import App
from kivy.core.window import Window
from kivy.uix.screenmanager import ScreenManager

from ui.decrypt_screen import DecryptScreen
from ui.encrypt_screen import EncryptScreen
from ui.main_screen import MainScreen
from ui.theme import COLORS

Window.clearcolor = COLORS["background"]


class PICRYPTApp(App):
    """Run the PICRYPT home, encryption, and decryption screens."""

    def build(self):
        manager = ScreenManager()
        manager.add_widget(MainScreen(name="home"))
        manager.add_widget(EncryptScreen(name="encrypt"))
        manager.add_widget(DecryptScreen(name="decrypt"))
        manager.current = "home"
        return manager


if __name__ == "__main__":
    PICRYPTApp().run()
