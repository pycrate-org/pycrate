"""
Protocol message parsers for various mobile network protocols.
Each parser function wraps the pycrate parsing function and returns
a structured dict with message type, decoded values, and remaining chunks.
"""
from regrets._utils import hex_to_bytes, extract_message_info


def parse_nas_mobile_originated(hex_bytes):
    """Parse a NAS Mobile-Originated message from hex bytes.
    
    Handles 2G/3G/4G NAS uplink messages including:
    - MM (Mobility Management) messages like Location Updating Request
    - CC (Call Control) messages like Setup, Alerting
    - SMS (Short Message Service) messages
    
    Args:
        hex_bytes: Hex-encoded string of the NAS MO message
    
    Returns:
        dict: {'msg_type': str|None, 'val': dict|None, 'chunks_left': int}
    """
    from pycrate_mobile.NAS import parse_NAS_MO
    msg, chunks = parse_NAS_MO(hex_to_bytes(hex_bytes))
    return extract_message_info(msg, chunks)


def parse_nas_mobile_terminated(hex_bytes):
    """Parse a NAS Mobile-Terminated message from hex bytes.
    
    Handles 2G/3G/4G NAS downlink messages including:
    - MM messages like Location Updating Accept/Reject
    - CC messages like Call Proceeding, Alerting
    - SMS messages
    
    Args:
        hex_bytes: Hex-encoded string of the NAS MT message
    
    Returns:
        dict: {'msg_type': str|None, 'val': dict|None, 'chunks_left': int}
    """
    from pycrate_mobile.NAS import parse_NAS_MT
    msg, chunks = parse_NAS_MT(hex_to_bytes(hex_bytes))
    return extract_message_info(msg, chunks)


def parse_gtpc_message(hex_bytes):
    """Parse a GTP-C (GPRS Tunnelling Protocol - Control) message from hex bytes.
    
    GTP-C is defined in 3GPP TS 29.274 and used in the 4G EPC for
    signalling between MME, SGW, and PGW. Common messages include
    Create Session Request/Response, Delete Session Request/Response,
    and Modify Bearer Request/Response.
    
    Args:
        hex_bytes: Hex-encoded string of the GTP-C message
    
    Returns:
        dict: {'msg_type': str|None, 'val': dict|None, 'chunks_left': int}
    """
    from pycrate_mobile.TS29274_GTPC import parse_GTPC
    msg, chunks = parse_GTPC(hex_to_bytes(hex_bytes))
    return extract_message_info(msg, chunks)


def parse_sccp_message(hex_bytes):
    """Parse an SCCP (Signalling Connection Control Part) message from hex bytes.
    
    SCCP is used in SS7 signalling for routing and connection management
    in mobile networks. It sits between MTP and higher-layer protocols
    like RANAP, BSSAP, and TCAP.
    
    Args:
        hex_bytes: Hex-encoded string of the SCCP message
    
    Returns:
        dict: {'msg_type': str|None, 'val': dict|None}
    """
    from pycrate_mobile.SCCP import parse_SCCP
    msg = parse_SCCP(hex_to_bytes(hex_bytes))
    if msg is not None:
        return {'msg_type': type(msg).__name__, 'val': msg.get_val_d()}
    return {'msg_type': None, 'val': None}
