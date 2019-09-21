"""
Utilities needed during the signing process
"""

import hashlib
import hmac


def sha256_hash(val):
    """
    Sha256 hash of text data.
    """
    return hashlib.sha256(val.encode('utf-8')).hexdigest()


def sha256_hash_for_binary_data(val):
    """
    Sha256 hash of binary data.
    """
    return hashlib.sha256(val).hexdigest()


def sign(key, msg):
    """
    Key derivation functions.
    See: http://docs.aws.amazon.com
    /general/latest/gr/signature-v4-examples.html
    #signature-v4-examples-python
    """
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
