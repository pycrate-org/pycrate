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
# * File Name : pycrate_gmr1_csn1/pdcp_capability_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.3.59         PDCP Capability
# top-level object: PDCP Capability IE

# external references
from pycrate_gmr1_csn1.data_compression_parameter_ie import data_compression_parameter_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

spare_bit = CSN1Bit(name='spare_bit')
Spare_bit = spare_bit
Spare_Bit = spare_bit

pdcp_capability_ie = CSN1List(name='pdcp_capability_ie', list=[
  CSN1Bit(name='pdcp_capability_length', bit=8),
  CSN1Bit(name='support_for_lossless_serving_rnc_relocation'),
  CSN1Alt(alt={
    '0': ('support_for_rfc_2507', []),
    '1': ('support_for_rfc_2507', [
    CSN1Bit(name='max_hc_context_space', bit=4)])}),
  CSN1Alt(alt={
    '0': ('support_for_rfc_3095', []),
    '1': ('support_for_rfc_3095', [
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='maximum_number_of_rohc_context_sessions', bit=4)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Bit(name='reverse_decompression_depth', bit=16)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [])})])}),
  CSN1Alt(alt={
    '0': ('support_for_pep', []),
    '1': ('support_for_pep', [
    CSN1Bit(name='support_for_pep_compression'),
    CSN1Bit(name='support_for_pep_handover')])}),
  CSN1Alt(alt={
    '0': ('support_for_data_compression', []),
    '1': ('support_for_data_compression', [
    CSN1Ref(name='data_compression_parameters', obj=data_compression_parameter_ie)])}),
  CSN1Ref(obj=spare_bit, num=-1)])
