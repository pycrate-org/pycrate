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
# * File Name : pycrate_gmr1_csn1/packet_dch_assignment_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-12
# section: 11.2.5b Packet DCH Assignment (Iu mode only)
# top-level object: Packet DCH Assignment message content

# external references
from pycrate_gmr1_csn1.channel_info_ie import channel_info_ie
from pycrate_gmr1_csn1.padding_bits import padding_bits
from pycrate_gmr1_csn1.slot_allocation_ie import slot_allocation_ie
from pycrate_gmr1_csn1.power_control_synch_offset_ie import power_control_synch_offset_ie
from pycrate_gmr1_csn1.pdch_mcs_ie import dch_mcs_ie
from pycrate_gmr1_csn1.packet_link_synchronization_ie import packet_link_synchronization_ie
from pycrate_gmr1_csn1.global_tfi_ie import global_tfi_ie
from pycrate_gmr1_csn1.frequency_parameters_ie import frequency_allocation_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

dch_tbf_allocation_ie = CSN1List(name='dch_tbf_allocation_ie', list=[
  CSN1Ref(name='channel_info', obj=channel_info_ie),
  CSN1Ref(name='power_control_synch_offset', obj=power_control_synch_offset_ie),
  CSN1Ref(name='dch_channel_mcs_info', obj=dch_mcs_ie),
  CSN1Alt(alt={
    '0': ('', [
    CSN1Bit(name='downlink_mac_slot_allocation', bit=8)]),
    '1': ('', [
    CSN1Ref(name='downlink_slot_allocation', obj=slot_allocation_ie)])}),
  CSN1Alt(alt={
    '0': ('', [
    CSN1Bit(name='uplink_mac_slot_allocation', bit=8)]),
    '1': ('', [
    CSN1Ref(name='uplink_slot_allocation', obj=slot_allocation_ie)])}),
  CSN1Bit(name='rb_id', bit=5)])

tbf_assignment_struct = CSN1List(name='tbf_assignment_struct', list=[
  CSN1Val(name='', val='0'),
  CSN1Ref(name='uplink_dch_tbf_allocation', obj=dch_tbf_allocation_ie),
  CSN1Val(name='', val='10'),
  CSN1Ref(name='uplink_and_downlink_dch_tbf_allocation', obj=dch_tbf_allocation_ie),
  CSN1Alt(alt={
    '0': ('', [
    CSN1Bit(bit=-1)]),
    None: ('', [])})])

packet_dch_assignment_message_content = CSN1List(name='packet_dch_assignment_message_content', list=[
  CSN1Alt(alt={
    '00': ('', []),
    '01': ('', [
    CSN1Ref(name='global_tfi', obj=global_tfi_ie)]),
    '10': ('', [
    CSN1Bit(name='g_rnti', bit=32)])}),
  CSN1List(list=[
    CSN1Val(name='', val='0'),
    CSN1Bit(name='rid', bit=2),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(name='frequency_allocation', obj=frequency_allocation_ie)])}),
    CSN1Alt(alt={
      '0': ('', []),
      '1': ('', [
      CSN1Ref(obj=packet_link_synchronization_ie)])}),
    CSN1Ref(name='tbf_assignment', obj=tbf_assignment_struct),
    CSN1Ref(obj=padding_bits)])])

