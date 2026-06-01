CAESAR_SHIFT = 3

_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _shift_alphabet_char(char, shift):
    if char in _LOWERCASE:
        alphabet = _LOWERCASE
    elif char in _UPPERCASE:
        alphabet = _UPPERCASE
    else:
        return char

    index = alphabet.index(char)
    return alphabet[(index + shift) % len(alphabet)]


def caesar_encrypt(message, shift=CAESAR_SHIFT):
    return "".join(_shift_alphabet_char(char, shift) for char in message)


def caesar_decrypt(message, shift=CAESAR_SHIFT):
    return caesar_encrypt(message, -shift)
