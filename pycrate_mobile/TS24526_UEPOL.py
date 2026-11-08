# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS24526_UEPOL.py
# * Created : 2019-12-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'URSPRules',
    'URSPRule',
    'WLANSPRule',
    'ANDSPInfos',
    'ANDSPInfo'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.526: User Equipment (UE) policies for 5G System (5GS)
# release 16 (g10)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from pycrate_ether.IP       import IPAddr, IPProt_dict
from pycrate_ether.Ethernet import EtherType_dict

from pycrate_mobile.TS29244_PFCP import FQDN
from pycrate_mobile.TS24008_IE   import PLMN
from pycrate_mobile.TS24501_IE   import (
    DNN, _SSCMode_dict, NSSAI, L_SNSSAI, PDUSESSTYPE, _PDUSessType_dict, FGSTAIList, 
    )


#------------------------------------------------------------------------------#
# Encoding of UE policy part type URSP
# TS 24.526, section 5.2
#------------------------------------------------------------------------------#

# Table 5.2.1, Traffic descriptor component type identifier
_TrafficDescCompType_dict = {
    1   : 'Match-all',
    8   : 'OS Id + OS App Id',
    16  : 'IPv4 remote address',
    33  : 'IPv6 remote address/prefix length',
    48  : 'Protocol identifier/next header',
    80  : 'Single remote port',
    81  : 'Remote port range',
    82  : 'IP 3-tuple',
    96  : 'Security parameter index',
    112 : 'Type of service/traffic class',
    128 : 'Flow label',
    129 : 'Destination MAC address',
    131 : '802.1Q C-TAG VID',
    132 : '802.1Q S-TAG VID',
    133 : '802.1Q C-TAG PCP/DEI',
    134 : '802.1Q S-TAG PCP/DEI',
    135 : 'Ethertype',
    136 : 'DNN',
    144 : 'Connection capabilities',
    145 : 'Destination FQDN',
    146 : 'Regular expression',
    160 : 'OS App Id',
    161 : 'Destination MAC address range',
    162 : 'PIN ID',
    163 : 'Connectivity group ID'
    }

_TrafficDescConCap_dict = {
    1   : 'IMS',
    2   : 'MMS',
    4   : 'SUPL',
    8   : 'Internet',
    16  : 'LCS user plane positioning',
    161 : 'IoT delay-tolerant',
    162 : 'IoT non-delay-tolerant',
    163 : 'Downlink streaming',
    164 : 'Uplink streaming',
    165 : 'Vehicular communications',
    166 : 'Real time interactive',
    167 : 'Unified communications',
    168 : 'Background',
    169 : 'Mission critical communications',
    170 : 'Time critical communications',
    171 : 'Low latency loss tolerant communications in unacknowledged mode'
    }


# Table 5.2.1, OS Id + OS App Id type
class _TrafficDescCompOSAppId(Envelope):
    _GEN = (
        Buf('OS_UUID', bl=128, rep=REPR_HEX),
        Uint8('LenAppId'),
        Buf('AppId')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


# Table 5.2.1, IPv4 remote address type
class _TrafficDescCompIPv4(Envelope):
    _GEN = (
        IPAddr('Addr', bl=32),
        IPAddr('Mask', bl=32)
        )


# Table 5.2.1, IPv6 remote address/prefix length type
class _TrafficDescCompIPv6(Envelope):
    _GEN = (
        IPAddr('Addr', bl=128),
        Uint8('PrefLen')
        )


# Table 5.2.1, remote port range type
class _TrafficDescCompPortRange(Envelope):
    _GEN = (
        Uint16('Low'),
        Uint16('High')
        )


# Table 5.2.1, IP 3 tuple type
class _TrafficDescCompIP3tuple(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('BMPortRange', bl=1),
        Uint('BMPort', bl=1),
        Uint('BMProtId', bl=1),
        Uint('BMIPv6Pref', bl=1),
        Uint('BMIPv4', bl=1),
        _TrafficDescCompIPv4('IPv4'),
        _TrafficDescCompIPv6('IPv6Pref'),
        Uint8('ProtId', dic=IPProt_dict),
        Uint16('Port'),
        _TrafficDescCompPortRange('PortRange'),
        )
    
    # Note on presence of subfields:
    # - Port and PortRange are exclusive
    # - IPv4 and IPv6Pref are exclusive
    # - At least one subfield must be set
    # In all other cases, the IP 3-tuple rule must be ignored by the receiver
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['IPv4'].set_transauto(lambda: self['BMIPv4'].get_val() == 0)
        self['IPv6Pref'].set_transauto(lambda: self['BMIPv6Pref'].get_val() == 0)
        self['ProtId'].set_transauto(lambda: self['BMProtId'].get_val() == 0)
        self['Port'].set_transauto(lambda: self['BMPort'].get_val() == 0)
        self['PortRange'].set_transauto(lambda: self['BMPortRange'].get_val() == 0)


# Table 5.2.1, type of service/traffic class type
class _TrafficDescCompTrafficClass(Envelope):
    _GEN = (
        Uint8('Class'),
        Uint8('Mask')
        )


# Table 5.2.1, flow label type
class _TrafficDescCompFlowLabel(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=20, rep=REPR_HEX)
        )


# Table 5.2.1, 802.1Q C-TAG VID type / 802.1Q S-TAG VID type
class _TrafficDescCompVID(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=12)
        )


# Table 5.2.1, 802.1Q C-TAG PCP/DEI type / 802.1Q S-TAG PCP/DEI type
class _TrafficDescCompPCPDEI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('PCP', bl=3),
        Uint('DEI', bl=1)
        )


# Table 5.2.1, connection capabilities type
class _TrafficDescCompConCap(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('Caps', GEN=Uint8('Cap', dic=_TrafficDescConCap_dict))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


# Table 5.2.1, destination FQDN type
class _TrafficDescCompFQDN(Envelope):
    _GEN = (
        Uint8('Len'),
        FQDN('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Table 5.2.1, regular expression type
class _TrafficDescCompRegExp(Envelope):
    _GEN = (
        Uint8('Len'),
        String('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Table 5.2.1, OS App Id type / PIN ID type / connectivity group ID type
class _TrafficDescCompLV(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Table 5.2.1, destination MAC address range type
class _TrafficDescCompMACRange(Envelope):
    _GEN = (
        Buf('Low', bl=48, rep=REPR_HEX),
        Buf('High', bl=48, rep=REPR_HEX),
        )


# Table 5.2.1, 
class TrafficDescComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_TrafficDescCompType_dict),
        Alt('Value', GEN={
            1   : Buf('none', bl=0),
            8   : _TrafficDescCompOSAppId('OSAppId'),
            16  : _TrafficDescCompIPv4('IPv4'),
            33  : _TrafficDescCompIPv6('IPv6Pref'),
            48  : Uint8('ProtId', dic=IPProt_dict),
            80  : Uint16('Port'),
            81  : _TrafficDescCompPortRange('PortRange'),
            82  : _TrafficDescCompIP3tuple('IP3tuple'),
            96  : Uint32('SPI', rep=REPR_HEX),
            112 : _TrafficDescCompTrafficClass('TrafficClass'),
            128 : _TrafficDescCompFlowLabel('FlowLabel'),
            129 : Buf('MACDest', bl=48, rep=REPR_HEX),
            131 : _TrafficDescCompVID('CTagVID'),
            132 : _TrafficDescCompVID('STagVID'),
            133 : _TrafficDescCompPCPDEI('CTagPCPDEI'),
            134 : _TrafficDescCompPCPDEI('STagPCPDEI'),
            135 : Uint16('EtherType', dic=EtherType_dict),
            136 : DNN(),
            144 : _TrafficDescCompConCap('ConCap'),
            145 : _TrafficDescCompFQDN('FQDN'),
            146 : _TrafficDescCompRegExp('RegExp'),
            160 : _TrafficDescCompLV('AppId'),
            161 : _TrafficDescCompMACRange('MACRange'),
            162 : _TrafficDescCompLV('PINID'),
            163 : _TrafficDescCompLV('ConGroupID')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    # Note: if the "match-all type" traffic descriptor component is included in a traffic descriptor,
    # there shall be no traffic descriptor component with a type other than "match-all type" in the traffic descriptor,
    # and it shall not appear more than once among all traffic descriptors of the whole URSP rules


# Table 5.2.1, SSC Mode Type
class _RouteSelectDescCompSSCMode(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('Value', bl=3, dict=_SSCMode_dict)
        )


# Table 5.2.1, PDU session type type type
class _RouteSelectDescCompPDUSessType(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Value', val=PDUSESSTYPE.IPV4, bl=3, dic=_PDUSessType_dict)
        )


# Table 5.2.1, preferred access type type
class _RouteSelectDescCompAccessType(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Value', bl=2, dic={1:'3GPP access', 2:'non-3GPP access'})
        )


# Table 5.2.1, time window type
# 64-bit NTP timestamps
class _RouteSelectDescCompTimeWin(Envelope):
    _GEN = (
        Envelope('StartTime', GEN=(
            Uint32('Sec'),
            Uint32('Fract')
            )),
        Envelope('StopTime', GEN=(
            Uint32('Sec'),
            Uint32('Fract')
            ))
        )


# Table 5.2.2: Location criteria
class _LocAreaEUTRACellID(Envelope):
    _GEN = (
        PLMN(),
        Buf('EUTRACellID', bl=28, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )


class _LocAreaCompEUtra(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('CellIDs', GEN=_LocAreaEUTRACellID('EUTRACellID'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


class _LocAreaNRCellID(Envelope):
    _GEN = (
        PLMN(),
        Buf('NRCellID', bl=36, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )


class _LocAreaCompNR(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('CellIDs', GEN=_LocAreaNRCellID('NRCellID'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


class _LocAreaGNBID(Envelope):
    _GEN = (
        PLMN(),
        Buf('GNBID', bl=32, rep=REPR_HEX)
        )


class _LocAreaCompGNBID(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('GNBIDs', GEN=_LocAreaGNBID('GNBID'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


# Table 5.2.2: Location area
_RouteSelectLocAreaType_dict = {
    1 : 'E-UTRA cell identities list',
    2 : 'NR cell identities list',
    3 : 'Global RAN node identities list',
    4 : 'TAI list'
    }


class _LocAreaComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_RouteSelectLocAreaType_dict),
        Alt('Cont', GEN={
            1 : _LocAreaCompEUtra('EUTRACellIDList'),
            2 : _LocAreaCompNR('NRCellIDList'),
            3 : _LocAreaCompGNBID('GNBIDList'),
            4 : FGSTAIList()
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.2.5: Location criteria
class _RouteSelectDescCompLocArea(Sequence):
    _GEN = _LocAreaComp('LocAreaComp')


# Table 5.2.1, Route selection descriptor component type identifier
_RouteSelectDescCompType_dict = {
    1   : 'SSC mode',
    2   : 'S-NSSAI',
    4   : 'DNN',
    8   : 'PDU session type',
    16  : 'Preferred access type',
    17  : 'Multi-access preference',
    32  : 'Non-seamless non-3GPP offload indication',
    64  : 'Location criteria',
    128 : 'Time window',
    129 : '5G ProSe layer-3 UE-to-network relay offload indication',
    130 : 'PDU session pair ID',
    131 : 'RSN',
    132 : '5G ProSe multi-path preference',
    }


class RouteSelectDescComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_RouteSelectDescCompType_dict),
        Alt('Value', GEN={
            1   : _RouteSelectDescCompSSCMode('SSCMode'),
            2   : L_SNSSAI(),
            4   : DNN(),
            8   : _RouteSelectDescCompPDUSessType('PDUSessType'),
            16  : _RouteSelectDescCompAccessType('AccessType'),
            17  : Buf('none', bl=0),
            32  : Buf('none', bl=0),
            64  : _RouteSelectDescCompLocArea('LocArea'),
            128 : _RouteSelectDescCompTimeWin('TimeWin'),
            129 : Buf('none', bl=0),
            130 : Uint8('PDUSessPairID'),
            131 : Uint8('RSN'),
            132 : Buf('none', bl=0)
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.2.4: Route selection descriptor
class RouteSelectDesc(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Precedence'),
        Uint16('LenCont'),
        Sequence('Cont', GEN=RouteSelectDescComp())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 3 + self['Cont'].get_len())
        self['LenCont'].set_valauto(lambda: self['Cont'].get_len())
        self['Cont'].set_blauto(lambda: self['LenCont'].get_val()<<3)


# Figure 5.2.2: URSP rule
class URSPRule(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Precedence'),
        Uint16('LenTrafficDesc'),
        Sequence('TrafficDesc', GEN=TrafficDescComp()),
        Uint16('LenRouteSelectDescList'),
        Sequence('RouteSelectDescList', GEN=RouteSelectDesc()),
        Buf('AddInd', val=b'', rep=REPR_HEX) # 0 or 1 byte (for now)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda:
            5 + self['TrafficDesc'].get_len() + self['RouteSelectDescList'].get_len() + self['AddInd'].get_len()
            )
        self['LenTrafficDesc'].set_valauto(lambda: self['TrafficDesc'].get_len())
        self['TrafficDesc'].set_blauto(lambda: self['LenTrafficDesc'].get_val()<<3)
        self['LenRouteSelectDescList'].set_valauto(lambda: self['RouteSelectDescList'].get_len())
        self['RouteSelectDescList'].set_blauto(lambda: self['LenRouteSelectDescList'].get_val()<<3)
        self['AddInd'].set_blauto(lambda:
            (self['Len'].get_val() - self['LenTrafficDesc'].get_val() - self['LenRouteSelectDescList'].get_val() - 5)<<3
            )


# Figure 5.2.1: UE policy part contents including one or more URSP rules
class URSPRules(Sequence):
    _GEN = URSPRule()
    
    # Note: multiple URSP rules in the URSP shall not have the same precedence value 


#------------------------------------------------------------------------------#
# Encoding of UE policy part type ANDSP
# TS 24.526, section 5.3
#------------------------------------------------------------------------------#

class SSID(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Figure 5.3.2.4g: Selection criteria sub entry {selection criteria set type = minimum backhaul threshold}
class _WLANSelectionCriteriaMinBack(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('ULBInd', bl=1),
        Uint('DLBInd', bl=1),
        Uint('NetworkType', bl=2, dic={0:'home', 1:'roaming'}),
        Uint32('DLBW'),
        Uint32('ULBW')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['DLBW'].set_transauto(lambda: self['DLBInd'].get_val() == 0)
        self['ULBW'].set_transauto(lambda: self['ULBInd'].get_val() == 0)


# Figure 5.3.2.4f: Selection criteria sub entry {selection criteria set type = SP exclusion list}
class _WLANSelectionCriteriaSPExcl(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('SSID')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Figure 5.3.2.4e: Selection criteria sub entry {selection criteria set type = required protocol port tuple}
class _WLANSelectionCriteriaPortTuple(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('ProtId', dic=IPProt_dict),
        Uint8('LenPort'),
        Buf('Port', val=b'\0\1', rep=REPR_HEX), # see WiFi Alliance HotSpot 2.0
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 2 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


# Figure 5.3.2.4d: Selection criteria sub entry {selection criteria set type = preferred roaming partner list}
class _WLANSelectionCriteriaPrefRoam(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Priority'),
        Uint8('LenFQDN_Match'),
        Buf('FQDN_Match', rep=REPR_HEX), # see WiFi Alliance HotSpot 2.0
        Uint8('LenCountry'),
        Buf('Country', rep=REPR_HEX), # see WiFi Alliance HotSpot 2.0
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 3 + self['FQDN_Match'].get_len() + self['Country'].get_len())
        self['LenFQDN_Match'].set_valauto(lambda: self['FQDN_Match'].get_len())
        self['FQDN_Match'].set_blauto(lambda: self['LenFQDN_Match'].get_val()<<3)
        self['LenCountry'].set_valauto(lambda: self['Country'].get_len())
        self['Country'].set_blauto(lambda: self['LenCountry'].get_val()<<3)


# Figure 5.3.2.4c: Selection criteria sub entry {selection criteria set type = preferred SSID list}

class _WLANSelectionCriteriaPrefSSID(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('WLANPriority'),
        Uint('spare', bl=6),
        Uint('HESSIDInd', bl=1),
        Uint('SSIDInd', bl=1),
        SSID(),
        Buf('HESSID', bl=48, rep=REPR_HEX) # MAC addr
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 2 + self['SSID'].get_len() + self['HESSID'].get_len())
        self['SSID'].set_transauto(lambda: self['SSIDInd'].get_val() == 0)
        self['HESSID'].set_transauto(lambda: self['HESSIDInd'].get_val() == 0)


# Figure 5.3.2.21: SSID list
class SSIDList(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('SSIDList', GEN=SSID()),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['SSIDList'].get_num())
        self['SSIDList'].set_numauto(lambda: self['Num'].get_val())


# Figure 5.3.2.4h:Selection criteria sub entry {selection criteria set type = slice-based TNAN list}
class _WLANSelectionCriteriaTNAN(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('LenTNGFID'),
        Buf('TNGFID', val=b''),
        NSSAI(),
        SSIDList()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda:
            1 + self['TNGFID'].get_len() + self['NSSAI'].get_len() + self['SSIDList'].get_len()
            )
        self['LenTNGFID'].set_valauto(lambda: self['TNGFID'].get_len())
        self['TNGFID'].set_blauto(lambda: self['LenTNGFID'].get_val()<<3)


# Figure 5.3.2.4b
_WLANSelCritType_dict = {
    1 : 'preferred SSID list',
    2 : 'preferred roaming partner list',
    3 : 'required protocol port tuple',
    4 : 'SP exclusion list',
    5 : 'minimum backhaul threshold',
    6 : 'slice-based TNAN list'
    }


class _WLANSelectionCriteriaSet(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('Type', bl=4, dic=_WLANSelCritType_dict),
        Uint('Num', bl=4),
        Sequence('SubEntries', GEN=Alt('CriteriaSubEntry', GEN={
            1 : _WLANSelectionCriteriaPrefSSID('PrefSSID'),
            2 : _WLANSelectionCriteriaPrefRoam('PrefRoam'),
            3 : _WLANSelectionCriteriaPortTuple('RequiredProtPort'),
            4 : _WLANSelectionCriteriaSPExcl('SPExcl'),
            5 : _WLANSelectionCriteriaMinBack('MinBackhaulThres'),
            6 : _WLANSelectionCriteriaTNAN('TNAN')},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Type'].get_val()))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 1 + self['SubEntries'].get_len())
        self['Num'].set_valauto(lambda: self['SubEntries'].get_num())
        self['SubEntries'].set_numauto(lambda: self['Num'].get_val())
        self['SubEntries'].set_blauto(lambda: (self['Len'].get_val() - 1)<<3)


# Table 5.3.2.1: WLANSP information element, Home network ind
_HomeNetworkInd_dict = {
    0 : 'all WLANs could match this selection criteria entry',
    1 : 'only the WLANs that are operated by the home operator could match this selection criteria entry'
    }


# Figure 5.3.2.4a
class _WLANSelectionCriteriaEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('spare', bl=1),
        Uint('MaxBSSLoadInd', bl=1),
        Uint('HomeNetworkInd', bl=1, dic=_HomeNetworkInd_dict),
        Uint('CriteriaPriority', bl=5),
        Uint16('MaxBSSLoad'),
        Sequence('CriteriaSets', GEN=_WLANSelectionCriteriaSet('CriteriaSet'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda:
            3 + self['CriteriaSets'].get_len() if self['MaxBSSLoadInd'].get_val() == 1 else \
            1 + self['CriteriaSets'].get_len()
            )
        self['MaxBSSLoad'].set_transauto(lambda: self['MaxBSSLoadInd'].get_val() == 0)
        self['CriteriaSets'].set_blauto(lambda:
            (self['Len'].get_val() - 3)<<3 if self['MaxBSSLoadInd'].get_val() == 1 else \
            (self['Len'].get_val() - 1)<<3
            )


# Figure 5.3.2.4
class _WLANSelectionCriteria(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Entries', GEN=_WLANSelectionCriteriaEntry('CriteriaEntry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


# Figure 5.3.2.11a: Location field {entry type= Geo location}
class _LocFieldGeo(Envelope):
    _GEN = (
        Uint32('Lat'),
        Uint32('Long'),
        Uint16('Radius')
        )


# Figure 5.3.2.10a: Location sub entry {entry type= WLAN location or Geo location}
class _LocSubentryGeo(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Fields', GEN=_LocFieldGeo('LocGeo'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.11c: Location field {entry type= WLAN location}
_LocFieldType_dict = {
    1 : 'TAC',
    2 : 'EUTRA CI',
    4 : 'NR CI',
    129 : 'HESSID',
    130 : 'SSID',
    132 : 'BSSID'
    }

class _LocFieldWLAN(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Type', dic=_LocFieldType_dict),
        Alt('Cont', GEN={
            129 : Buf('HESSID', bl=48, rep=REPR_HEX),
            130 : Buf('SSID', rep=REPR_HEX), # SSID should be no more than 32 bytes
            132 : Buf('BSSID', bl=48, rep=REPR_HEX),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.10a: Location sub entry {entry type= WLAN location or Geo location}
class _LocSubentryWLAN(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Fields', GEN=_LocFieldWLAN('LocWLAN'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.11b: Location field {entry type= 3GPP location}
class _LocField3GPP(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Type', dic=_LocFieldType_dict),
        Alt('Cont', GEN={
            1   : Uint24('TAC', rep=REPR_HEX),
            2   : Envelope('EUTRA_CI', GEN=(
                    Uint('spare', bl=4, rep=REPR_HEX),
                    Uint('Value', bl=28, rep=REPR_HEX),
                )),
            4   : Envelope('NR_CI', GEN=(
                    Uint('spare', bl=4, rep=REPR_HEX),
                    Uint('Value', bl=36, rep=REPR_HEX),
                )),
            # Not sure those should be there for Loc3GPP
            129 : Buf('ESSID', bl=48, rep=REPR_HEX),
            130 : Buf('SSID'), # SSID should be no more than 32 bytes
            132 : Buf('BSSID', bl=48, rep=REPR_HEX),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.10: Location sub entry {entry type= 3GPP location}
class _LocSubentry3GPP(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Uint8('Num'), # optional
        Sequence('Fields', GEN=_LocField3GPP('Loc3GPP'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 4 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())
        self[3].set_blauto(lambda: (self[0].get_val() - 4)<<3)


# Figure 5.3.2.6: Location entry
class LocationEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('Type', bl=2, dic={1:'3GPP', 2:'WLAN', 3:'Geo'}),
        Uint('Num', bl=6),
        Sequence('SubEntries', GEN=Alt('LocationSubEntry', GEN={
            1 : _LocSubentry3GPP('SubEntry3GPP'),
            2 : _LocSubentryWLAN('SubEntryWLAN'),
            3 : _LocSubentryGeo('SubEntryGeo')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Type'].get_val()))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())
        self[3].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.5: Validity area
class _WLANValidityArea(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Entries', GEN=LocationEntry())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.20: ToD sub field {field type = "day of the week"}
class _TimeOfDayDoW(Envelope):
    _GEN = (
        Uint('spare', val=1, bl=1),
        Uint('Mon', bl=1),
        Uint('Tue', bl=1),
        Uint('Wed', bl=1),
        Uint('Thu', bl=1),
        Uint('Fri', bl=1),
        Uint('Sat', bl=1),
        Uint('Sun', bl=1)
        )


# Figure 5.3.2.17: ToD sub field
_TimeOfDayFieldType_dict = {
    1 : 'time start',
    2 : 'time stop',
    4 : 'date start',
    8 : 'date stop',
    16 : 'day of the week'
    }

class _TimeOfDayField(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Type', dic=_TimeOfDayFieldType_dict),
        Alt('Cont', GEN={
            # Next 4 are date strings, as defined in ISO 8601:2004
            1 : Buf('TimeStart'),
            2 : Buf('TimeStop'),
            4 : Buf('DateStart'),
            8 : Buf('DateStop'),
            16 : _TimeOfDayDoW('DayOfWeek')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Type'].get_val())
        )


# Figure 5.3.2.16: Time of day sub field
class _TimeOfDayEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Fields', GEN=_TimeOfDayField('TimeOfDayField'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.15: Time of day
class _WLANTimeOfDay(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Entries', GEN=_TimeOfDayEntry('TimeOfDayEntry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())
        self[2].set_blauto(lambda: (self[0].get_val() - 1)<<3)


# Figure 5.3.2.3
class WLANSPRule(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Id'),
        Uint8('Priority'),
        Uint('Roaming', bl=1, dic={
            0 : 'rule only valid when UE is not roaming',
            1 : 'rule only valid when UE is roaming'}),
        Uint('ValidityAreaInd', bl=1),
        Uint('3GPPLocInd', bl=1),
        Uint('WLANLocInd', bl=1),
        Uint('GeoLocInd', bl=1),
        Uint('TimeOfDayInd', bl=1),
        Uint('spare', bl=2, rep=REPR_HEX),
        _WLANSelectionCriteria('SelectionCriteria'),
        _WLANValidityArea('ValidityArea'), # optional
        _WLANTimeOfDay('TimeOfDay') # optional
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda:
            3 + self['SelectionCriteria'].get_len() + self['ValidityArea'].get_len() + self['TimeOfDay'].get_len()
            )
    
    # The 2 indicators for ValidityArea and TimeOfDay are used to hint about existing content
    # in the ValidityArea and TimeOfDay
    # The 3 indicators for 3GPPLoc, WLANLoc and GeoLoc are used to hint about what exists
    # in the ValidityArea


# Figure 5.3.3.2.2: N3AN node selection information entry
_N3ANNodeSelFQDNFmt_dict = {
    0 : 'Operator identifier based ePDG FQDN format or operator identifier based N3IWF FQDN',
    1 : 'Tracking/location area identity based ePDG FQDN format or tracking area identity based N3IWF FQDN format'
    }

class _N3ANNodeSelEntry(Envelope):
    _GEN = (
        Uint8('Len'),
        PLMN(),
        Uint('FQDNFmt', bl=2, dic=_N3ANNodeSelFQDNFmt_dict),
        Uint('Preference', bl=1, dic={0:'N3IWF is preferred', 1:'ePDG is preferred'}),
        Uint('Priority', bl=5),
        Buf('ext', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 4 + self['ext'].get_len())
        self['ext'].set_blauto(lambda: (self['Len'].get_val() - 4)<<3)


# Figure 5.3.3.3.2: Home N3IWF identifier entry (Home N3IWF identifier type = "IPv4", "IPv6" or "IPv4v6")
# Figure 5.3.3.3.3: Home N3IWF identifier entry (Home N3IWF identifier type = "FQDN")
# Figure 5.3.3.3.4: Home N3IWF identifier entry (Home N3IWF identifier type = "SNPN FQDN")
class _HomeN3IWFIdentEntrySNPNFQDN(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint('MCCDigit2', bl=4),
        Uint('MCCDigit1', bl=4),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('MCCDigit3', bl=4),
        FQDN()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 2 + self['FQDN'].get_len())
        self['FQDN'].set_blauto(lambda: (self['Len'].get_val() - 2)<<3)


class _HomeN3IWFIdentEntry(Envelope):
    _GEN = (
        Uint8('Type', val=1, dic={1:'IPv4', 2:'IPv6', 3:'IPv4v6', 4:'FQDN', 5:'SNPN FQDN'}),
        Alt('', GEN={
            1 : IPAddr('IPv4', bl=32, rep=REPR_HEX),
            2 : IPAddr('IPv6', bl=128, rep=REPR_HEX),
            3 : Envelope('IPv4v6', GEN=(
                    IPAddr('IPv4', bl=32, rep=REPR_HEX),
                    IPAddr('IPv6', bl=128, rep=REPR_HEX))
                ),
            4 : _TrafficDescCompFQDN('FQDN'),
            5 : _HomeN3IWFIdentEntrySNPNFQDN('SNPNFQDN'),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.3.3.4.2: Home ePDG identifier entry (Home ePDG identifier type = "IPv4", "IPv6" or "IPv4v6")
# Figure 5.3.3.4.3: Home ePDG identifier entry (Home ePDG identifier type = "FQDN")
class _HomeEPDGIdentEntry(Envelope):
    _GEN = (
        Uint8('Type', val=1, dic={1:'IPv4', 2:'IPv6', 3:'IPv4v6', 4:'FQDN'}),
        Alt('', GEN={
            1 : IPAddr('IPv4', bl=32, rep=REPR_HEX),
            2 : IPAddr('IPv6', bl=128, rep=REPR_HEX),
            3 : Envelope('IPv4v6', GEN=(
                    IPAddr('IPv4', bl=32, rep=REPR_HEX),
                    IPAddr('IPv6', bl=128, rep=REPR_HEX))
                ),
            4 : _TrafficDescCompFQDN('FQDN'),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.3.3.5.2: Extended home N3IWF identifier entry
class _ExtHomeN3IWFIdentEntry(Envelope):
    _GEN = (
        _HomeN3IWFIdentEntry('HomeN3IWFEntry'),
        NSSAI()
        )


# Figure 5.3.3.6.2: slice-specific N3IWF prefix entry
class _SSN3IWFPrefixConfig(Envelope):
    _GEN = (
        FQDN('Prefix'), # should be a single label
        NSSAI()
        )


# Table 5.3.3.1.2: Content of N3AN node configuration informatio
_N3ANNodeConfigInfoType_dict = {
    1 : 'Home N3IWF identifier',
    2 : 'Home ePDG identifier',
    3 : 'Extended home N3IWF identifier',
    4 : 'Slice-specific N3IWF prefix'
    }

# Figure 5.3.3.1.2: N3AN node configuration information contents
class N3ANNodeConfig(Envelope):
    _GEN = (
        Uint16('LenSelInfo'),
        Sequence('SelInfo', GEN=_N3ANNodeSelEntry('SelEntry')),
        #
        Uint8('TypeHomeN3IWF', val=1, dic=_N3ANNodeConfigInfoType_dict),
        Uint16('LenHomeN3IWFI'),
        Sequence('HomeN3IWF', GEN=_HomeN3IWFIdentEntry('HomeN3IWFEntry')),
        #
        Uint8('TypeHomeEPDG', val=2, dic=_N3ANNodeConfigInfoType_dict),
        Uint16('LenHomeEPDG'),
        Sequence('HomeEPDG', GEN=_HomeEPDGIdentEntry('HomeEPDGEntry')),
        #
        Uint8('TypeExtHomeN3IWF', val=3, dic=_N3ANNodeConfigInfoType_dict),
        Uint16('LenExtHomeN3IWFI'),
        Sequence('ExtHomeN3IWF', GEN=_ExtHomeN3IWFIdentEntry('ExtHomeN3IWFEntry')),
        #
        Uint8('TypeSSN3IWFPref', val=4, dic=_N3ANNodeConfigInfoType_dict),
        Uint16('LenSSN3IWFPref'),
        Sequence('SSN3IWFPref', GEN=_SSN3IWFPrefixConfig('SSN3IWFPrefEntry')),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['LenSelInfo'].set_valauto(lambda: self['SelInfo'].get_len())
        self['SelInfo'].set_blauto(lambda: self['LenSelInfo'].get_val()<<3)
        self['LenHomeN3IWFI'].set_valauto(lambda: self['HomeN3IWF'].get_len())
        self['HomeN3IWF'].set_blauto(lambda: self['LenHomeN3IWFI'].get_val()<<3)
        self['LenHomeEPDG'].set_valauto(lambda: self['HomeEPDG'].get_len())
        self['HomeEPDG'].set_blauto(lambda: self['LenHomeEPDG'].get_val()<<3)
        self['LenExtHomeN3IWFI'].set_valauto(lambda: self['ExtHomeN3IWF'].get_len())
        self['ExtHomeN3IWF'].set_blauto(lambda: self['LenExtHomeN3IWFI'].get_val()<<3)
        self['LenSSN3IWFPref'].set_valauto(lambda: self['SSN3IWFPref'].get_len())
        self['SSN3IWFPref'].set_blauto(lambda: self['LenSSN3IWFPref'].get_val()<<3)


# Table 5.3.1.1: ANDSP information format
_ANDSPInfoType_dict = {
    0 : 'Reserved',
    1 : 'WLANSP',
    2 : 'N3AN node configuration information'
    }


# Figure 5.3.1.3: ANDSP Info
# Figure 5.3.2.1: ANDSP Info type = {WLANSP}
# Figure 5.3.3.1.1: ANDSP info containing N3AN node configuration information, where x=k
class ANDSPInfo(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', val=1, bl=4, dic=_ANDSPInfoType_dict),
        Uint16('Len'),
        Alt('Cont', GEN={
            1: Sequence('WLANSPRules', GEN=WLANSPRule()),
            2: N3ANNodeConfig()
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


# Figure 5.3.1.1: UE policy part when UE policy part type = {ANDSP}
class ANDSPInfos(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', val=2, bl=4, dic={2:'ANDSP'}),
        Sequence('Cont', GEN=ANDSPInfo())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: 1 + self['Cont'].get_len())
        self['Cont'].set_blauto(lambda: (self['Len'].get_val() - 1)<<3)
