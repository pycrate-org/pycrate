"""
Shared utilities for pycrate Regrets wrappers.
Provides common hex conversion and Envelope decoding helpers.
"""
from binascii import unhexlify


def hex_to_bytes(hex_str):
    """Convert a hex-encoded string to raw bytes.
    
    Args:
        hex_str: String of hexadecimal digits (e.g. '50ab01')
    
    Returns:
        bytes: The decoded byte sequence
    """
    return unhexlify(hex_str)


def decode_envelope_to_dict(envelope_class, hex_bytes):
    """Decode a pycrate Envelope subclass from hex bytes to a value dict.
    
    Creates an instance of the given Envelope class, decodes the provided
    hex-encoded bytes into it, and returns the resulting value dictionary.
    
    Args:
        envelope_class: A pycrate Envelope subclass (e.g. AccessType, DNN)
        hex_bytes: Hex-encoded string of the raw bytes to decode
    
    Returns:
        dict: The decoded value dictionary from the Envelope instance
    """
    instance = envelope_class()
    instance.from_bytes(hex_to_bytes(hex_bytes))
    return instance.get_val_d()


def encode_envelope_from_dict(envelope_class, value_dict):
    """Encode a value dict into a pycrate Envelope and return hex bytes.
    
    Creates an instance of the given Envelope class, sets its value from
    the provided dictionary, and returns the encoded bytes as a hex string.
    
    Args:
        envelope_class: A pycrate Envelope subclass
        value_dict: Dict of field values to encode
    
    Returns:
        str: Hex-encoded string of the encoded bytes
    """
    instance = envelope_class()
    instance.set_val(value_dict)
    return instance.to_bytes().hex()


def extract_message_info(msg, chunks_remaining):
    """Extract type name and value dict from a parsed pycrate message.
    
    Handles both successful parses (msg is not None) and failed parses
    (msg is None), returning a consistent dict structure.
    
    Args:
        msg: A pycrate Element subclass instance, or None if parse failed
        chunks_remaining: Number of unconsumed bytes after parsing
    
    Returns:
        dict: {'msg_type': str|None, 'val': dict|None, 'chunks_left': int}
    """
    if msg is not None:
        return {
            'msg_type': type(msg).__name__,
            'val': msg.get_val_d(),
            'chunks_left': chunks_remaining,
        }
    return {'msg_type': None, 'val': None, 'chunks_left': chunks_remaining}
