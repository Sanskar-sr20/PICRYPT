[app]

# (str) Title of your application
title = PICRYPT

# (str) Package name
package.name = picrypt

# (str) Package domain (needed for Android application IDs)
package.domain = org.picrypt

# (str) Source code directory
source.dir = .

# (list) Source files to include
source.include_exts = py,png,jpg,jpeg,pdf,kv,atlas

# (str) Application entry point
entrypoint = main.py

# (list) Android/runtime dependencies for the initial APK.
# jpeglib, av, numpy, pymupdf, pytest, and FFmpeg are intentionally omitted.
requirements = python3,kivy,pillow,pycryptodome,pypdf

# (str) Supported orientation
orientation = portrait

# (str) Android application version
version = 0.1.0

# (bool) Recommended for Kivy applications
fullscreen = 0

[buildozer]

# (str) Log level (0 = error, 1 = warning, 2 = info, 3 = debug)
log_level = 2

# (str) Warn when the build directory is missing
warn_on_root = 1
