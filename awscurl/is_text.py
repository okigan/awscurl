# Based on the source code published on from http://code.activestate.com/recipes/173220-test-if-a-file-or-string-is-text-or-binary/
# Licensed under the PSF License

# Try using Python 3 function. If it fails, fallback to Python 2
try:
    _null_trans = str.maketrans("", "")
except AttributeError:
    import string
    _null_trans = string.maketrans("", "")

text_characters = "".join(list(map(chr, range(32, 127))) + list("\n\r\t\b"))


def is_text(s):
    """
    Returns true if 's' does not contain a \0, is empty, or
    if less than 30% are non-text characters.
    """

    if "\0" in s:
        return 0

    if not s:
        return 1

    t = s.translate(_null_trans, text_characters)

    if len(t)/len(s) > 0.30:
        return 0

    return 1
