from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.label import Label


class KeyboardTestApp(App):

    def build(self):
        layout = BoxLayout(
            orientation="vertical",
            padding=40,
            spacing=20
        )

        label = Label(
            text="Click the box and type: HELLO PICRYPT",
            size_hint_y=None,
            height=60
        )

        text_input = TextInput(
            multiline=True,
            size_hint_y=None,
            height=150
        )

        layout.add_widget(label)
        layout.add_widget(text_input)

        return layout


if __name__ == "__main__":
    KeyboardTestApp().run()
