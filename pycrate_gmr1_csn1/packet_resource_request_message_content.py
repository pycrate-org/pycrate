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
# * File Name : pycrate_gmr1_csn1/packet_resource_request_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-12
# section: 11.2.16 Packet resource request (Iu mode only)
# top-level object: Packet Resource Request message content

# external references
from pycrate_gmr1_csn1.global_tfi_ie import global_tfi_ie
from pycrate_gmr1_csn1.iu_mode_channel_request_description_ie import iu_mode_channel_request_description_ie
from pycrate_gmr1_csn1.padding_bits import padding_bits

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

packet_resource_request_message_content = CSN1List(name='packet_resource_request_message_content', list=[
  CSN1List(list=[
    CSN1Val(name='', val='0'),
    CSN1Ref(name='global_tfi', obj=global_tfi_ie),
    CSN1Val(name='', val='10'),
    CSN1Bit(name='g_rnti', bit=32)]),
  CSN1Bit(name='retransmission_of_prr'),
  CSN1Ref(name='iu_mode_channel_request_description', obj=iu_mode_channel_request_description_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Bit(name='hfn_lsb')])}),
  CSN1Ref(obj=padding_bits)])
