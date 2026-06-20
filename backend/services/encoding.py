import base64
import urllib.parse
import binascii

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def decode_base64(text: str) -> str:
    try:
        return base64.b64decode(text.encode('utf-8')).decode('utf-8')
    except Exception:
        return "Invalid Base64"

def encode_url(text: str) -> str:
    return urllib.parse.quote(text)

def decode_url(text: str) -> str:
    return urllib.parse.unquote(text)

def encode_hex(text: str) -> str:
    return binascii.hexlify(text.encode('utf-8')).decode('utf-8')

def decode_hex(text: str) -> str:
    try:
        return binascii.unhexlify(text.encode('utf-8')).decode('utf-8')
    except Exception:
        return "Invalid Hex"

def encode_binary(text: str) -> str:
    return ' '.join(format(ord(c), '08b') for c in text)

def decode_binary(text: str) -> str:
    try:
        binary_values = text.replace(' ', '')
        return ''.join(chr(int(binary_values[i:i+8], 2)) for i in range(0, len(binary_values), 8))
    except Exception:
        return "Invalid Binary"

MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', 
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', 
    '8': '---..', '9': '----.', ' ': '/'
}
REVERSE_MORSE_DICT = {value: key for key, value in MORSE_CODE_DICT.items()}

def encode_morse(text: str) -> str:
    try:
        return ' '.join(MORSE_CODE_DICT.get(c, '') for c in text.upper())
    except Exception:
        return "Error encoding Morse"

def decode_morse(text: str) -> str:
    try:
        return ''.join(REVERSE_MORSE_DICT.get(c, '?') for c in text.split(' '))
    except Exception:
        return "Error decoding Morse"
