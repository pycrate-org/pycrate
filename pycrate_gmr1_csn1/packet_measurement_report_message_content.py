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
# * File Name : pycrate_gmr1_csn1/packet_measurement_report_message_content.py
# * Created : 2023-10-24
# * Authors : Benoit Michau
# *--------------------------------------------------------
#*/
# specification: ETSI TS 101 376-04-12
# section: 11.2.9a Packet Measurement Report (Iu mode only)
# top-level object: Packet Measurement Report message content

# external references
from pycrate_gmr1_csn1.padding_bits import padding_bits

# code automatically generated by pycrate_csn1
# change object type with type=CSN1T_BSTR (default type is CSN1T_UINT) in init
# add dict for value interpretation with dic={...} in CSN1Bit init
# add dict for key interpretation with kdic={...} in CSN1Alt init

from pycrate_csn1.csnobj import *

gps_position_ie = CSN1Val(name='gps_position_ie', val='null')

distance_ie = CSN1Val(name='distance_ie', val='null')

gmr_measurement_report_struct = CSN1List(name='gmr_measurement_report_struct', list=[
  CSN1Bit(name='rxlev_serving_cell', bit=6),
  CSN1Bit(name='number_of_measurements', bit=3),
  CSN1List(num=([1], lambda x: x), list=[
    CSN1Bit(name='gmr_cell_list_index', bit=5),
    CSN1Bit(name='rxlev', bit=6)])])

_3g_measurement_report_struct = CSN1List(name='_3g_measurement_report_struct', list=[
  CSN1Bit(name='n_3g', bit=3),
  CSN1List(num=([0], lambda x: x + 1), list=[
    CSN1Bit(name='_3g_cell_list_index', bit=7),
    CSN1Bit(name='reporting_quantity', bit=6)])])

position_measurement_report_struct = CSN1Alt(name='position_measurement_report_struct', alt={
  '0': ('', [
  CSN1Ref(name='mes_gps_position', obj=gps_position_ie)]),
  '10': ('', [
  CSN1Ref(name='distance_information', obj=distance_ie)])})

gmr_3g_measurement_report_struct = CSN1List(name='gmr_3g_measurement_report_struct', list=[
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='gmr_measurement_report', obj=gmr_measurement_report_struct)])}),
  CSN1Alt(alt={
    '0': ('', []),
    '1': ('', [
    CSN1Ref(name='_3g_measurement_report', obj=_3g_measurement_report_struct)])})])

packet_measurement_report_message_content = CSN1List(name='packet_measurement_report_message_content', list=[
  CSN1Bit(name='g_rnti', bit=32),
  CSN1Bit(name='request_reference', bit=8),
  CSN1Alt(alt={
    '0': ('', [
    CSN1Ref(name='position_measurement_report', obj=position_measurement_report_struct)]),
    '10': ('', [
    CSN1Ref(name='gmr_3g_measurement_report', obj=_3g_measurement_report_struct)])}),
  CSN1Ref(obj=padding_bits)])
