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
# * File Name : pycrate_gmr1_csn1/capability_update_requirement_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.3.4         Capability Update Requirement
# top-level object: Capability Update Requirement IE



# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

spare_bits = CSN1Bit(name='spare_bits', num=-1)
Spare_bits = spare_bits
Spare_Bits = spare_bits

capability_update_requirement_ie = CSN1List(name='capability_update_requirement_ie', list=[
  CSN1Bit(name='capability_update_requirement_length', bit=4),
  CSN1Bit(name='mes_geran_iu_mode_radio_access_capability_update_requirement'),
  CSN1Bit(name='mes_geran_a_gb_mode_radio_access_capability_update_requirement'),
  CSN1Bit(name='ue_radio_capability_fdd_capability_update_requirement'),
  CSN1Bit(name='ue_radio_capability_3_84_mcps_tdd_capability_update_requirement'),
  CSN1Bit(name='ue_radio_capability_1_28_mcps_tdd_capability_update_requirement'),
  CSN1Bit(name='ue_cdma2000_radio_access_capability_update_requirement'),
  CSN1Ref(obj=spare_bits)])
