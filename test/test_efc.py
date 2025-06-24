from pycrate_asn1dir.EFC_2023 import EfcDsrcGeneric, EfcDataDictionary

# Sample DSRC tests, especially for T-APDUs (L7)
BeaconID = EfcDsrcGeneric.BeaconID
BeaconID.set_val({
  'manufacturerid': 0x1,
  'individualid': 1052 #41C
  })
print(BeaconID.to_asn1())
print("BeaconID UPER:", BeaconID.to_uper().hex().upper())

BST = EfcDsrcGeneric.BST
utc_ts = 1103790512

bst_value = {
  'rsu': {
    'manufacturerid': 0x1,
    'individualid': 1052 #41C
    },
  'time':utc_ts,
  'profile': 0,
  'mandApplications': [
    {
    'aid': 3
    }
    ],
  'profileList': []
  }
BST.set_val(bst_value)

print(f"BST encoded in UPER in hex: {BST.to_uper().hex().upper()}")
print()

print("We now get an UPER-encoded EFC-CM and decode it...")
contract_provider_uper_hex = "30C001"
toc = 0x0001
cv = 0x02
efc_cm_uper_hex = f"{contract_provider_uper_hex}{toc:04X}{cv:02X}"
print(f"UPER-encoded EFC-CM in hex str format: {efc_cm_uper_hex}")
EfcContextMark = EfcDataDictionary.EfcContextMark
efc_cm_uper_bytes = bytes.fromhex(f"{efc_cm_uper_hex}")
EfcContextMark.from_uper(efc_cm_uper_bytes)
print("EFC-CM represented as JSON (following JER):", EfcContextMark.to_jer())

print()
print("We now use .set_val() to set the EFC-CM value and later encode it in UPER ...")
efc_cm = {
  'contractProvider': {
    'countryCode': (195, 10),
    'providerIdentifier': 1
    },
  'typeOfContract': b'\x00\x01',
  'contextVersion': 2
  }
EfcContextMark.set_val(efc_cm)
print(EfcContextMark.to_asn1())
print("Encoding EFC-CM in UPER and representing as hex str:", EfcContextMark.to_uper().hex().upper())

EfcContainer = EfcDsrcGeneric.EfcContainer
EfcContainer.set_val(('efccontext', EfcContextMark._val))
print(EfcContainer.to_asn1())

EfcContainer.set_val(('attrList', [
  {
  'attributeId': 0,
  'attributeValue': ('octetstring', efc_cm_uper_bytes)
  }
]))
print("EFC Container with AttrList encoded in UPER in hex:", EfcContainer.to_uper().hex().upper())
print(EfcContainer.to_asn1())

print("We now get to the most important part: encoding/decoding EFC T-APDUs (ISO 15628)")
print("Sending a BST...")

t_apdu_init_req = bytes.fromhex("807FF8000100674F0C38000301141D0100")
EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_init_req)
print(EfcDsrcGeneric.T_APDUs.to_asn1())

print("Receiving VST...")
# BR in ITA2/baudot is 10011 01010 (=0x9A8 aligned to the left)
t_apdu_init_resp = bytes.fromhex("900002C10402069A8001000102D40302109A8001000101020200FF0204C8A11E6E800100020000")
EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_init_resp)
print(EfcDsrcGeneric.T_APDUs.to_asn1())

print("Sending GET.request")
t_apdu_get_req = bytes.fromhex("6A0304ACCE55C80110")
EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_get_req)
print(EfcDsrcGeneric.T_APDUs.to_asn1())

print("Receiving GET.response")
t_apdu_get_resp = bytes.fromhex("740301102FB280085745522D30303031")
EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_get_resp)
print(EfcDsrcGeneric.T_APDUs.to_asn1())

print("Sending ACTION.request with GET_STAMPED.request parameter")
fragmented_t_apdu_action_req = bytes.fromhex("0D030004ACCE55C811012004FFFFFFFFF")
EfcDsrcGeneric.T_APDUs.from_uper(fragmented_t_apdu_action_req)
print(EfcDsrcGeneric.T_APDUs.to_asn1())

print("Receiving ACTION.response with GET_STAMPED.response parameter")
fragmented_t_apdu_action_resp = bytes.fromhex("1403120120400F0F0F0F0F0F0F0F0F0F599F000004FFFFFFFF")
EfcDsrcGeneric.T_APDUs.from_uper(fragmented_t_apdu_action_resp)
print(EfcDsrcGeneric.T_APDUs.to_asn1())