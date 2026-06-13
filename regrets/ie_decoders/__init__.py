"""
5G NAS Information Element (IE) decoders and encoders.
Each function handles a specific IE type from TS 24.501.
"""
from regrets._utils import decode_envelope_to_dict, encode_envelope_from_dict


def _get_access_type_class():
    """Lazy import of AccessType to avoid loading all of TS24501_IE at module level."""
    from pycrate_mobile.TS24501_IE import AccessType
    return AccessType


def decode_access_type(hex_bytes):
    """Decode 5G NAS AccessType IE from hex bytes to value dict.
    
    The AccessType IE is defined in TS 24.501 Section 9.11.2.1A.
    It indicates whether the access is 3GPP or non-3GPP.
    
    Args:
        hex_bytes: Hex-encoded string (e.g. '50' for spare=1, Value=1)
    
    Returns:
        dict: {'spare': int, 'Value': int} where Value 1='3GPP access', 2='non-3GPP access'
    """
    return decode_envelope_to_dict(_get_access_type_class(), hex_bytes)


def encode_access_type(val_dict):
    """Encode 5G NAS AccessType IE from value dict to hex bytes.
    
    Args:
        val_dict: {'spare': int, 'Value': int}
    
    Returns:
        str: Hex-encoded bytes
    """
    return encode_envelope_from_dict(_get_access_type_class(), val_dict)


def _get_dnn_class():
    """Lazy import of DNN to avoid loading all of TS24501_IE at module level."""
    from pycrate_mobile.TS24501_IE import DNN
    return DNN


def decode_dnn(hex_bytes):
    """Decode 5G NAS DNN (Data Network Name) IE from hex bytes to value dict.
    
    The DNN IE is defined in TS 24.501 Section 9.11.2.1B.
    It identifies the data network (equivalent to APN in 4G).
    
    Args:
        hex_bytes: Hex-encoded string of the DNN IE
    
    Returns:
        dict: Decoded DNN value dictionary
    """
    return decode_envelope_to_dict(_get_dnn_class(), hex_bytes)


def decode_5gs_tracking_area_id(hex_bytes):
    """Decode 5G NAS 5GSTrackingAreaIdentity IE from hex bytes to value dict.
    
    The 5G TAI IE identifies a tracking area in the 5G core network.
    It contains a PLMN ID and a Tracking Area Code.
    
    Args:
        hex_bytes: Hex-encoded string of the 5G TAI IE
    
    Returns:
        dict: Decoded tracking area identity value dictionary
    """
    from pycrate_mobile.TS24501_IE import FiveGSTrackingAreaIdentity
    return decode_envelope_to_dict(FiveGSTrackingAreaIdentity, hex_bytes)


def lookup_security_header_type(value):
    """Look up 5G NAS Security Header Type description by numeric value.
    
    The Security Header Type is defined in TS 24.501 Section 9.3.1.
    It indicates the security protection applied to the NAS message.
    
    Args:
        value: Integer security header type value (0-4)
    
    Returns:
        str: Human-readable description (e.g. 'Integrity protected')
    """
    from pycrate_mobile.TS24501_IE import SecHdrType_dict
    return SecHdrType_dict.get(value, 'reserved')
