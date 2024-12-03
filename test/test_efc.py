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
get_resp_t_apdu_bytes = b't\x04\x01 @\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fY_\x00\x00'
print(f"T-APDU containing Get-Response encoded in UPER in hex: {get_resp_t_apdu_bytes.hex().upper()}")
EfcDsrcGeneric.T_APDUs.from_uper(get_resp_t_apdu_bytes)

print(f"Python T-APDU value:\n{EfcDsrcGeneric.T_APDUs._val}")
print(f"T-APDU encoded in JER: {EfcDsrcGeneric.T_APDUs.to_jer()}")