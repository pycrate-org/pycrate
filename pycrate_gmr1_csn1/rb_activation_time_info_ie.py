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
# * File Name : pycrate_gmr1_csn1/rb_activation_time_info_ie.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-13
# section: 9.3.77        RB Activation Time Info
# top-level object: RB Activation Time Info IE

# external references
from pycrate_gmr1_csn1.rb_identity_ie import rb_identity_ie

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

repeated_radio_bearer_activation_time_struct = CSN1List(name='repeated_radio_bearer_activation_time_struct', list=[
  CSN1Ref(name='rb_identity', obj=rb_identity_ie),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Alt(alt={
      '00': ('', [
      CSN1Bit(name='gmprs_rlc_sequence_number', bit=10)]),
      '01': ('', [
      CSN1Val(name='reserved', val='null')]),
      '10': ('', [
      CSN1Bit(name='dcch_tbf_mode_rlc_sequence_number', bit=7)]),
      '11': ('', [
      CSN1Val(name='reserved', val='null')])})])})])

rb_activation_time_info_ie = CSN1Alt(name='rb_activation_time_info_ie', alt={
  '0': ('', []),
  '1': ('', [
  CSN1Bit(name='repeated_radio_bearer_activation_time_list', bit=5),
  CSN1Ref(name='repeated_radio_bearer_activation_time', obj=repeated_radio_bearer_activation_time_struct, num=([1], lambda x: x + 1))])})
