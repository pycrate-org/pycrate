# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018. Benoit Michau. P1sec.
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
# * File Name : pycrate_gmr1_csn1/mes_capability_information_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.2.25           MES CAPABILITY INFORMATION
# top-level object: MES CAPABILITY INFORMATION message content

# external references
from pycrate_gmr1_csn1.rrc_transaction_identifier_ie import rrc_transaction_identifier_ie
from pycrate_gmr1_csn1.ue_utran_radio_access_capability_extension_ie import ue_utran_radio_access_capability_extension_ie
from pycrate_gmr1_csn1.mes_geran_a_gb_mode_radio_access_capability_ie import mes_geran_a_gb_mode_radio_access_capability_ie
from pycrate_gmr1_csn1.ue_utran_radio_access_capability_ie import ue_utran_radio_access_capability_ie
from pycrate_gmr1_csn1.ue_utran_predefined_configuration_status_information_ie import ue_utran_predefined_configuration_status_information_ie
from pycrate_gmr1_csn1.ue_cdma2000_radio_access_capability_ie import ue_cdma2000_radio_access_capability_ie
from pycrate_gmr1_csn1.mes_geran_iu_mode_radio_access_capability_ie import mes_geran_iu_mode_radio_access_capability_ie
from pycrate_gmr1_csn1.integrity_check_info_ie import integrity_check_info_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

mes_capability_information_message_content = CSN1List(name='mes_capability_information_message_content', list=[
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='rrc_transaction_identifier', obj=rrc_transaction_identifier_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='integrity_check_info', obj=integrity_check_info_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='mes_geran_iu_mode_radio_access_capability', obj=mes_geran_iu_mode_radio_access_capability_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='mes_geran_a_gb_mode_radio_access_capability', obj=mes_geran_a_gb_mode_radio_access_capability_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='ue_utran_radio_access_capability', obj=ue_utran_radio_access_capability_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='ue_utran_radio_access_capability_extension', obj=ue_utran_radio_access_capability_extension_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='ue_utran_predefined_configuration_status_information', obj=ue_utran_predefined_configuration_status_information_ie)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='ue_cdma2000_radio_access_capability', obj=ue_cdma2000_radio_access_capability_ie)])})])

