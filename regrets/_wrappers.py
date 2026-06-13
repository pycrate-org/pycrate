"""
Regrets wrapper functions for pycrate.
Provides Regrets-compatible entry points for pycrate's class-based API.

Architecture:
    _utils.py         — Shared hex conversion and Envelope helpers
    ie_decoders/      — Information Element (IE) decode/encode functions
    msg_parsers/      — Protocol message parsing functions

This module re-exports all functions for backward compatibility with
existing manifest.json references.
"""

# Re-export all public functions from the decomposed modules
from regrets._utils import hex_to_bytes, decode_envelope_to_dict, encode_envelope_from_dict, extract_message_info

# IE decoders — renamed for clarity, old names preserved as aliases
from regrets.ie_decoders import (
    decode_access_type,
    encode_access_type,
    decode_dnn,
    decode_5gs_tracking_area_id,
    lookup_security_header_type,
)

# Message parsers — renamed for clarity, old names preserved as aliases
from regrets.msg_parsers import (
    parse_nas_mobile_originated,
    parse_nas_mobile_terminated,
    parse_gtpc_message,
    parse_sccp_message,
)

# Backward-compatible aliases for existing manifest.json references
parse_nas_mo = parse_nas_mobile_originated
parse_nas_mt = parse_nas_mobile_terminated
parse_gtpc = parse_gtpc_message
parse_sccp = parse_sccp_message
decode_security_hdr_type = lookup_security_header_type
