# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.8
# *
# * Copyright 2026. Benoit Michau. P1Sec.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : test/test_dsrc.py
# * Created : 2026-05-27
# * Authors : Wesley Rodrigues Machado
# *--------------------------------------------------------
#*/

from pycrate_asn1dir.EFC_2023 import EfcDsrcGeneric, EfcDataDictionary
from pycrate_asn1dir.IE_2025  import EfcInfoExchange

# Sample DSRC tests, especially for T-APDUs (L7)

expected_beacon_id_uper = bytes.fromhex("000100008380")
def test_efc_beacon_id():
  BeaconID = EfcDsrcGeneric.BeaconID
  BeaconID.set_val({
    'manufacturerid': 0x1,
    'individualid': 1052 #41C
    })

  # print(BeaconID.to_asn1())
  # print("BeaconID UPER:", BeaconID.to_uper().hex().upper())
  assert expected_beacon_id_uper == BeaconID.to_uper()

expected_bst_uper = bytes.fromhex("0000800041C41CA81B0000103000")
def test_efc_bst():
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

  assert expected_bst_uper == BST.to_uper()

"""
countryCode = 195 = 0b 00110 00011 = NO (baudot ITA2)
providerId  = 1   = 0b 000001
contractProvider  = 0b0011 0000 1100 0001 = 0x30 C0 01
toc         = 1   = 0x0001
cv          = 2   = 0x02
"""
expected_efc_cm_val = {
  'contractProvider': {
    'countryCode': (195, 10),
    'providerIdentifier': 1
    },
  'typeOfContract': b'\x00\x01',
  'contextVersion': 2
  }
efc_cm_uper_bytes = bytes.fromhex("30C001000102")
def test_efc_efc_cm():
  EfcContextMark = EfcDataDictionary.EfcContextMark

  EfcContextMark.from_uper(efc_cm_uper_bytes)

  assert expected_efc_cm_val == EfcContextMark._val

  return expected_efc_cm_val

def test_efc_efc_container():
  EfcContainer = EfcDsrcGeneric.EfcContainer
  EfcContainer.set_val(('efccontext', expected_efc_cm_val))

  EfcContainer.set_val(('attrList', [
    {
    'attributeId': 0,
    'attributeValue': ('octetstring', efc_cm_uper_bytes)
    }
  ]))

def test_efc_t_apdus():
  T_APDUs = EfcDsrcGeneric.T_APDUs

  t_apdu_init_req = bytes.fromhex("807FF8000100674F0C38000301141D0100")
  T_APDUs.from_uper(t_apdu_init_req)
  init_req_jval = EfcDsrcGeneric.T_APDUs._to_jval()
  assert 'initialisation-request' in init_req_jval
  assert init_req_jval['initialisation-request']['time'] == 1733233720

  t_apdu_init_resp = bytes.fromhex("900002C10402069A8001000102D40302109A8001000101020200FF0204C8A11E6E800100020000")
  EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_init_resp)
  init_resp_jval = EfcDsrcGeneric.T_APDUs._to_jval()
  assert 'initialisation-response' in init_resp_jval
  # The second application is CCC: AID = 20
  assert init_resp_jval['initialisation-response']['applications'][1]['aid'] == 20

  t_apdu_get_req = bytes.fromhex("6A0304ACCE55C80110")
  EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_get_req)
  get_req_jval = EfcDsrcGeneric.T_APDUs._to_jval()
  assert 'get-request' in get_req_jval

  t_apdu_get_resp = bytes.fromhex("740301102FB280085745522D30303031")
  EfcDsrcGeneric.T_APDUs.from_uper(t_apdu_get_resp)
  get_resp_jval = EfcDsrcGeneric.T_APDUs._to_jval()
  assert 'get-response' in get_resp_jval

  fragmented_t_apdu_action_req = bytes.fromhex("0D030004ACCE55C811012004FFFFFFFFFF")
  EfcDsrcGeneric.T_APDUs.from_uper(fragmented_t_apdu_action_req)
  action_req_jval = EfcDsrcGeneric.T_APDUs._to_jval()
  assert 'action-request' in action_req_jval

  fragmented_t_apdu_action_resp = bytes.fromhex("1403120120400F0F0F0F0F0F0F0F0F0F599F000004FFFFFFFF")
  EfcDsrcGeneric.T_APDUs.from_uper(fragmented_t_apdu_action_resp)
  action_resp_jval = EfcDsrcGeneric.T_APDUs._to_jval()
  assert 'action-response' in action_resp_jval

mrd_1 = {
  'measuredPosition': {
    'latitude': 0,
    'longitude': 0,
  },
  'timeWhenMeasured': "20260415203000.0Z",
  'additionalGnssData': "",
}

mrd_2 = {
  'measuredPosition': {
    'latitude': 0,
    'longitude': 0,
  },
  'timeWhenMeasured': "20260415203000.0+0200",
  'additionalGnssData': "",
}

usage_statement_jval = {
   'usageStatementId': 1,
   'tollContextOperator': {
    'countryCode': 'b280',
    'providerIdentifier': 1,
   },
   'listOfRawUsageData': {
      'rawDataList': [
        mrd_1,
        mrd_2,
      ]
   }
}
def test_ie_usage_statement():
  # TODO: Improve if XML encoding/decoding is implemented
  EfcInfoExchange.UsageStatement._from_jval(usage_statement_jval)
  assert 'listOfRawUsageData' in EfcInfoExchange.UsageStatement._val