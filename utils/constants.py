"""Project-wide constants for PICRYPT."""

APP_NAME = "PICRYPT"
SUPPORTED_IMAGE_FORMATS = {".png", ".jpg", ".jpeg"}
MAX_MESSAGE_LENGTH_WARNING = "Message length exceeds image capacity."
INVALID_IMAGE_MESSAGE = "The selected file is not a valid image."
INVALID_PAYLOAD_MESSAGE = "The image does not contain a valid PICRYPT payload."

MAGIC_HEADER = b"PICRYPT"
PAYLOAD_VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 16
LENGTH_FIELD_SIZE = 4
