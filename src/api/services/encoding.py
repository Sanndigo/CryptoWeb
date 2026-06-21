import base64
import urllib.parse
import binascii


# ── Base64 ───────────────────────────────────────────────────────────────────

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode('utf-8'), validate=True).decode('utf-8')
    except Exception:
        return "Invalid Base64"


# ── URL ──────────────────────────────────────────────────────────────────────

def encode_url(text: str) -> str:
    return urllib.parse.quote(text)

def decode_url(text: str) -> str:
    return urllib.parse.unquote(text)


# ── Hex ──────────────────────────────────────────────────────────────────────

def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode('utf-8')).decode('utf-8')

def decode_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode('utf-8')).decode('utf-8')
    except Exception:
        return "Invalid Hex"


# ── Binary ───────────────────────────────────────────────────────────────────
# Operate on UTF-8 *bytes* so non-ASCII (Cyrillic, emoji, etc.) round-trip correctly.

def encode_binary(text: str) -> str:
    return ' '.join(format(b, '08b') for b in text.encode('utf-8'))

def decode_binary(text: str) -> str:
    try:
        bits = text.replace(' ', '')
        if len(bits) % 8 != 0:
            return "Invalid Binary"
        byte_vals = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
        return byte_vals.decode('utf-8')
    except Exception:
        return "Invalid Binary"


# ── Morse ────────────────────────────────────────────────────────────────────

MORSE_CODE_DICT: dict[str, str] = {
    'A': '.-',   'B': '-...',  'C': '-.-.',  'D': '-..',   'E': '.',
    'F': '..-.',  'G': '--.',   'H': '....',  'I': '..',    'J': '.---',
    'K': '-.-',   'L': '.-..',  'M': '--',    'N': '-.',    'O': '---',
    'P': '.--.',  'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',  'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    ' ': '/',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.',  '(': '-.--.',  ')': '-.--.-', '&': '.-...',  ':': '---...',
    ';': '-.-.-.', '=': '-...-',  '+': '.-.-.',  '-': '-....-',  '_': '..--.-',
    '"': '.-..-.', '$': '...-..-','@': '.--.-.',
}

REVERSE_MORSE_DICT: dict[str, str] = {v: k for k, v in MORSE_CODE_DICT.items()}


def encode_morse(text: str) -> str:
    try:
        return ' '.join(MORSE_CODE_DICT.get(c, '?') for c in text.upper())
    except Exception:
        return "Error encoding Morse"


def decode_morse(text: str) -> str:
    """
    Characters are separated by a single space; words are separated by ' / '.
    Empty tokens (from multiple spaces) are silently ignored.
    """
    try:
        tokens = [t for t in text.split(' ') if t]
        return ''.join(REVERSE_MORSE_DICT.get(tok, '?') for tok in tokens)
    except Exception:
        return "Error decoding Morse"
