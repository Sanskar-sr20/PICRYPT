# PICRYPT

## Project description
PICRYPT is a secure-message application that hides encrypted secret text inside digital images using a combination of AES-256 encryption and LSB image steganography. The system is designed as a semester project focused on secure communication, image-based concealment, and practical Python application development.

## Objective
The main objective of PICRYPT is to allow a user to:
- select a cover image,
- enter a secret message and password,
- encrypt the message with AES-256,
- hide the encrypted payload inside an image using LSB steganography,
- later extract and decrypt the hidden content using the correct password.

## Technology stack
- Python 3.8+
- Kivy
- Pillow
- PyCryptodome
- VS Code
- PyInstaller for future Windows packaging
- Buildozer for future Android packaging

## Current development status
Phases 1-5 are implemented. The project provides AES-256-CBC encryption/decryption, SHA-256 key derivation from `password + salt`, random 16-byte salt and IV generation, PKCS7 padding, PICRYPT payload serialization/parsing, RGB LSB embedding/extraction, capacity validation, safe output handling, the service integration layer, and a functional Kivy GUI for encryption and decryption.

## Planned architecture
The project uses a modular layout:
- `main.py` for the application entry point
- `ui/` for Kivy screens and interface logic
- `crypto/` for encryption and key management modules
- `steganography/` for LSB embedding and extraction logic
- `utils/` for validation, constants, and payload helpers
- `picrypt/` for high-level crypto and steganography integration services
- `ui/` for Kivy home, encryption, decryption, and file chooser screens
- `tests/` for unit, integration, and service tests

## Installation
1. Open a terminal in the project folder.
2. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

3. Activate the virtual environment:

   On Windows:
   ```bash
   .venv\Scripts\activate
   ```

   On macOS/Linux:
   ```bash
   source .venv/bin/activate
   ```

4. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Running the application
After installing dependencies, run:

```bash
python main.py
```

## Android packaging

The desktop dependency set in `requirements.txt` is intentionally unchanged.
The initial Android dependency set is maintained separately in
`requirements-android.txt` and is mirrored by `buildozer.spec`. It contains
only Kivy, Pillow, PyCryptodome, and pypdf; test dependencies, `jpeglib`,
NumPy, PyMuPDF, PyAV, and FFmpeg are excluded from this first APK.

This configuration is packaging preparation only; do not start a build until
the Android toolchain is configured. On Android, `ui/format_support.py` lazily
leaves out the optional `jpeglib` and `av` services. The Android GUI exposes
PNG and PDF only and explicitly marks JPEG and MP4 as unavailable until their
native services are supported. Desktop startup and the desktop JPEG and MP4
paths remain unchanged.

Desktop uses `FileChooserListView` and filesystem paths as before. Android uses
the Storage Access Framework document picker, copies selected PNG/PDF content
URIs into an app-private cache file before service processing, and keeps
generated output in that cache until the user exports it with
`ACTION_CREATE_DOCUMENT`. No Android storage permission is added; broad legacy
storage permissions are not a safe substitute for the document picker on
modern Android.

## Development roadmap
- Completed: project structure and dependency setup
- Completed: AES-256-CBC encryption/decryption module
- Completed: PICRYPT payload format and metadata handling
- Completed: RGB LSB embedding/extraction and capacity validation
- Completed: crypto and steganography integration tests
- Completed: Phase 4 service/integration layer and safe output handling
- Completed: Phase 5 Kivy GUI with encryption, decryption, previews, navigation, and save/download handling
- In progress: initial Android packaging configuration and GUI integration
- Future: native Android JPEG and MP4 carrier services

## Kivy GUI

Run the application with:

```bash
python main.py
```

The GUI provides Home, Encrypt, and Decrypt screens. The Encrypt screen lets the user choose a PNG, JPG, or JPEG cover image, enter a message and password, generate a stego image through `encrypt_image`, preview the result, and save a copy through the `DOWNLOAD / SAVE IMAGE` action. Saving does not re-encrypt the message.

The Decrypt screen lets the user choose a stego image, enter the password, call `decrypt_image`, display the recovered message, and copy it to the clipboard. User-facing validation and service errors are shown as short status messages; passwords and keys are never displayed or logged.

The GUI is a presentation layer only. AES, payload serialization, and LSB operations remain in their existing modules behind the service API. PNG is preferred for steganographic output because JPEG compression can damage embedded LSB data.

## Service Layer

The Phase 4 service layer in `picrypt/service.py` gives a future GUI simple high-level operations without exposing crypto, payload, or LSB internals:

```python
from picrypt.service import decrypt_image, encrypt_image

stego_path = encrypt_image(
      input_image="cover.png",
      output_image="PICRYPT_stego.png",
      message="Secret message",
      password="StrongPassword123!",
)

message = decrypt_image(stego_path, "StrongPassword123!")
```

`encrypt_image` validates the cover image, message, password, output path, and capacity. It writes the stego image through a temporary file and only replaces the requested output after embedding and saving succeed. It returns the actual output `Path`, which can later be connected to a GUI Download/Save Image action.

`decrypt_image` extracts the PICRYPT payload, validates its header and length, and delegates decryption to the existing AES module. Wrong passwords and corrupted data produce controlled errors instead of returning unverified plaintext.

PNG is preferred for steganographic output because it is lossless. JPEG compression can damage LSB-embedded data; JPEG can be used as a cover-image input, but it is not a safe lossless steganographic output format.

## Cryptography Design

PICRYPT uses a password-based AES-256 encryption workflow for the cryptography phase. The crypto engine is integrated with the RGB LSB steganography engine and exposed to the Kivy GUI through the service layer.

### 1. Password
The user supplies a plaintext password for encryption and decryption. The password is never stored in the payload and never written into the image.

### 2. Random salt
A random 16-byte salt is generated for every encryption operation using a cryptographically secure random source. This salt is included in the serialized payload so the same password can derive the same AES key during decryption.

### 3. SHA-256 key derivation
The project specification requires the design:

Password + Salt
      ↓
SHA-256
      ↓
32-byte AES-256 key

The key is derived as:

```python
key = sha256(password_bytes + salt).digest()
```

This produces exactly 32 bytes, which is suitable for AES-256.

### 4. AES-256
AES-256 provides confidentiality for the message. The project uses the AES cipher from PyCryptodome.

### 5. CBC mode
The encryption mode is AES-256-CBC. CBC requires a random IV and uses PKCS7 padding so that the message length fits the block size.

### 6. Random IV
A random 16-byte IV is generated for each encryption to provide unique ciphertext for the same plaintext under the same password.

### 7. PKCS7 padding
Before encryption, the plaintext is padded using PKCS7. After decryption, the padding is removed after successful validation.

### 8. Payload structure
The encrypted payload is a binary format used by the LSB embedding engine:

```text
Password + Salt
      ↓
SHA-256
      ↓
32-byte AES-256 Key
      ↓
AES-256-CBC + IV
      ↓
Ciphertext
      ↓
PICRYPT Payload
```

The payload contains:
- magic header: PICRYPT
- version
- salt
- IV
- ciphertext length
- ciphertext

The payload does not contain the plaintext password, the plaintext message, or the AES key.

### 9. Decryption process
During decryption:
1. Load the PICRYPT payload.
2. Validate the magic header and version.
3. Recover the salt and IV.
4. Re-derive the same SHA-256 key from the entered password + salt.
5. Decrypt the ciphertext using AES-256-CBC.
6. Remove PKCS7 padding.
7. Decode the plaintext UTF-8 message.

If the password is wrong or the ciphertext is corrupted, the code raises a clear decryption error instead of returning partial plaintext.

> The LSB module embeds and extracts the encrypted payload; it does not perform encryption or decryption.

## LSB Steganography

Phase 3 adds the steganographic layer to the encrypted PICRYPT payload. This phase does not replace the cryptography module; it works with the serialized payload created by Phase 2.

### What LSB means
LSB means Least Significant Bit. In an RGB image, each color channel stores 8 bits of information. By changing only the least significant bit of each channel, the image appearance remains visually nearly identical while hidden data is encoded.

### Why RGB channels are used
The RGB image format is a natural place for simple LSB embedding because each pixel contains three channels: red, green, and blue. The module processes each channel in a deterministic order and modifies only the final bit of each channel value.

### How embedding works
The encrypted PICRYPT payload is treated as opaque binary data. Each byte is converted into 8 bits and then written into the LSB of successive RGB channels.

```text
Encrypted PICRYPT Payload
        ↓
Binary Bits
        ↓
RGB Image LSBs
        ↓
Stego Image
```

### How extraction works
The stego image is read in the same deterministic pixel/channel order. The least significant bits are recovered and reassembled into bytes, then parsed as a PICRYPT payload.

```text
Stego Image
        ↓
RGB LSB Extraction
        ↓
PICRYPT Payload
        ↓
AES Decryption
```

### Capacity calculation
For an RGB image using one bit per channel, the theoretical capacity is:

```text
capacity_bits = width × height × 3
capacity_bytes = capacity_bits // 8
```

Before embedding, the module checks whether the serialized payload fits inside the available capacity. If the payload is too large, the operation is rejected and the stego image is not partially written.

### Image format guidance
PNG is preferred for steganographic output because it is lossless and preserves the embedded LSB data. JPEG compression can alter pixel channel values and damage or destroy the embedded payload. JPEG may be used as a cover-image input, but JPEG is not a safe lossless steganographic output format; save the generated stego image as PNG.

### Difference between encryption and steganography
- Encryption makes the message unreadable.
- Steganography hides the existence of the message.

PICRYPT combines both layers: the message is encrypted first, and then the encrypted payload is hidden inside the image.

> Phase 3 performs steganographic embedding and extraction only. AES encryption/decryption remains in the cryptography module.

## Notes
This project intentionally follows the required design for the semester assignment:
- AES-256 for message confidentiality
- SHA-256 for password-based key derivation
- random salt and IV
- encrypted payload serialization
- LSB steganography for hidden payload embedding
- secure validation and graceful error handling

This repository keeps AES, payload serialization, LSB steganography, service orchestration, and GUI presentation in separate modules. Windows executable packaging and Android packaging are not implemented.

## Developer

**PICRYPT — Secure Message & Image Steganography System**

Developed by **Sanskar Sandip Rewale**

GitHub: [@Sanskar-sr20](https://github.com/Sanskar-sr20)

© 2026 Sanskar Rewale