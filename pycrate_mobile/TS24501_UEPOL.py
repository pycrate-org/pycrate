# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.7
# *
# * Copyright 2019. Benoit Michau. P1Sec.
# * Copyright 2024. Benoit Michau
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
# * File Name : pycrate_mobile/TS24501_UEPOL.py
# * Created : 2019-12-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: UE policy delivery service (annex D)
# release 17 (hd0)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007       import *
from .TS24526_UEPOL import *
from .TS24588_UEPOL import *
from .TS24008_IE    import (
    PLMN, PLMNList,
    )


#------------------------------------------------------------------------------#
# UE policy delivery service message type
# TS 24.501, section D.6.1
#------------------------------------------------------------------------------#

_UEPolMsgType_dict = {
    0 : 'Reserved',
    1 : 'MANAGE UE POLICY COMMAND',
    2 : 'MANAGE UE POLICY COMPLETE',
    3 : 'MANAGE UE POLICY COMMAND REJECT',
    4 : 'UE STATE INDICATION',
    5 : 'UE POLICY PROVISIONING REQUEST', # defined in TS 24.587
    6 : 'UE POLICY PROVISIONING REJECT', # defined in TS 24.587
    }

class FGUEPOLHeader(Envelope):
    _name = '5GUEPOLHeader'
    _GEN = (
        Uint8('PTI'),
        Uint8('Type', val=1, dic=_UEPolMsgType_dict)
        )


#------------------------------------------------------------------------------#
# UE policy section management list
# TS 24.501, section D.6.2
#------------------------------------------------------------------------------#

_UEPolPartType_dict = {
    0 : 'Reserved',
    1 : 'URSP',
    2 : 'ANDSP',
    3 : 'V2XP',
    4 : 'ProSeP',
    5 : 'A2XP',
    6 : 'RSLPP',
    }


class UEPolPart(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', bl=4, dic=_UEPolPartType_dict),
        Alt('Cont', GEN={
            1 : URSPRules(),
            2 : ANDSPInfos(),
            3 : V2XPInfos(),
            # TODO: ProSePInfos(), see TS 24.555
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[3].get_len()+1)
        self[3].set_blauto(lambda: (self[0].get_val()-1)<<3)


class UEPolInstr(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint16('UPSC', rep=REPR_HEX),
        Sequence('Cont', GEN=UEPolPart())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[2].get_len()+2)
        self[2].set_blauto(lambda: (self[0].get_val()-2)<<3)


class UEPolSectionSublist(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Sequence('Cont', GEN=UEPolInstr())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3+self[2].get_len())
        self[2].set_blauto(lambda: (self[0].get_val()-3)<<3)


class UEPolSectionList(Sequence):
    _GEN = UEPolSectionSublist()


#------------------------------------------------------------------------------#
# UE policy section management result
# TS 24.501, section D.6.3
#------------------------------------------------------------------------------#

class UEPolResult(Envelope):
    _GEN = (
        Uint16('UPSC', rep=REPR_HEX),
        Uint16('FailedInstructionOrder', rep=REPR_HEX),
        Uint8('Cause', val=111, dic={111:'Protocol error, unspecified'})
        )


class UEPolSectionSubresult(Envelope):
    _GEN = (
        Uint8('Num'),
        PLMN(),
        Sequence('Cont', GEN=UEPolResult())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[0].get_val())


class UEPolSectionResult(Sequence):
    _GEN = UEPolSectionSubresult()


#------------------------------------------------------------------------------#
# UPSI list
# TS 24.501, section D.6.4
#------------------------------------------------------------------------------#

class UPSISublist(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Array('Cont', GEN=Uint16('UPSC', rep=REPR_HEX))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[2].get_len()+3)
        self[2].set_blauto(lambda: (self[0].get_val()-3)<<3)


class UPSIList(Sequence):
    _GEN = UPSISublist()


#------------------------------------------------------------------------------#
# UE policy classmark
# TS 24.501, section D.6.5
#------------------------------------------------------------------------------#

class UEPolCm(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('ANDSPSupp', bl=1),
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# UE OS Id
# TS 24.501, section D.6.6
#------------------------------------------------------------------------------#

class UEOSId(Array):
    _GEN = Buf('OS_UUID', bl=128, rep=REPR_HEX)


#------------------------------------------------------------------------------#
# UE policy network classmark
# TS 24.501, section D.6.7
#------------------------------------------------------------------------------#

class UEPolNetCm(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('NSSUI', bl=1),
        Buf('spare', val=b'', rep=REPR_HEX)
        )
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# VPS URSP configuration
# TS 24.501, section D.6.8
#------------------------------------------------------------------------------#

class _VPSURSPConfigVPLMNs(Envelope):
    _GEN = (
        Uint8('Num'),
        PLMNList()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())
    
    def decode(self):
        return [self['Num'].get_val(), self['PLMNList'].decode()]


class _VPSURSPConfigMCCs(Envelope):
    _GEN = (
        Uint8('Num'),
        Buf('Values', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self._get_num_mccs())
        self[1].set_blauto(lambda: self._get_len_mccs())
    
    def _get_num_mccs(self):
        mccs_len  = self['Values'].get_len()
        num, rest = mccs_len // 3, mccs_len % 3
        if rest:
            # odd number of MCCs
            num += 1
        return num
    
    def _get_len_mccs(self):
        mccs_num = self['Num'].get_val()
        if mccs_num % 2:
            # odd number of MCCs
            return ((mccs_num//2)*3 + 2)<<3
        else:
            return ((mccs_num//2)*3)<<3
    
    # Note: we're missing proper encoding / decoding for those nested MCC pairs


class _VPSURSPConfigNetDesc(Envelope):
    _GEN = (
        Uint8('Type', val=2, dic={1: 'one or more VPLMNs', 2: 'one or more MCCs', 3: 'any VPLMN'}),
        Alt('Entries', GEN={
            1 : _VPSURSPConfigVPLMNs('VPLMNs'),
            2 : _VPSURSPConfigMCCs('MCCs'),
            3 : Buf('none', bl=0),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


class _VPSURSPConfigTuple(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('ID'),
        Uint8('NumNetDescs'),
        Sequence('NetDescs', GEN=_VPSURSPConfigNetDesc('NetDesc'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['NetDescs'].get_len() + 2)
        self['NumNetDescs'].set_valauto(lambda: self['NetDescs'].get_num())
        self['NetDescs'].set_numauto(lambda: self['NumNetDescs'].get_val())


class VPSURSPConfig(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('RT', val=1, bl=2, dic={1: 'per-tuple replacement', 2: 'full list of tuples'}),
        Sequence('Tuples', GEN=_VPSURSPConfigTuple('Tuple'))
        )


#------------------------------------------------------------------------------#
# Manage UE policy command
# TS 24.501, section D.5.1
#------------------------------------------------------------------------------#

class FGUEPOLManageUEPolCmd(Layer3):
    _name = '5GUEPOLManageUEPolCmd'
    _GEN = (
        FGUEPOLHeader(val={'Type':1}),
        Type6LVE('UEPolSectionList', val={'V':b'\0\x09\0\7\0\xf1\x10\0\2\0\0'}, IE=UEPolSectionList()),
        Type4TLV('UEPolNetCm', val={'T':0x42, 'V':b'\0'}, IE=UEPolNetCm()),
        Type6TLVE('VPSURSPConfig', val={'T': 0x70, 'V':b'\1' }, IE=VPSURSPConfig())
        )


#------------------------------------------------------------------------------#
# Manage UE policy complete
# TS 24.501, section D.5.2
#------------------------------------------------------------------------------#

class FGUEPOLManageUEPolCmpl(Layer3):
    _name = '5GUEPOLManageUEPolCmpl'
    _GEN = (
        FGUEPOLHeader(val={'Type':2}),
        )


#------------------------------------------------------------------------------#
# Manage UE policy command reject
# TS 24.501, section D.5.3
#------------------------------------------------------------------------------#

class FGUEPOLManageUEPolRej(Layer3):
    _name = '5GUEPOLManageUEPolRej'
    _GEN = (
        FGUEPOLHeader(val={'Type':3}),
        Type6LVE('UEPolSectionResult', val={'V':b'\1\0\xf1\x10\0\0\0\0\x6f'}, IE=UEPolSectionResult()),
        )


#------------------------------------------------------------------------------#
# UE state indication
# TS 24.501, section D.5.4
#------------------------------------------------------------------------------#

class FGUEPOLStateInd(Layer3):
    _name = '5GUEPOLStateInd'
    _GEN = (
        FGUEPOLHeader(val={'Type':4}),
        Type6LVE('UPSIList', val={'V':b'\0\5\0\xf1\x10\0\0'}, IE=UPSIList()),
        Type4LV('UEPolCm', val={'V':b'\0'}, IE=UEPolCm()),
        Type4TLV('UEOSId', val={'T':0x41, 'V':16*b'\0'}, IE=UEOSId())
        )


#------------------------------------------------------------------------------#
# 5G UE Policy dispatcher
#------------------------------------------------------------------------------#

FGUEPOLTypeClasses = {
    1 : FGUEPOLManageUEPolCmd,
    2 : FGUEPOLManageUEPolCmpl,
    3 : FGUEPOLManageUEPolRej,
    4 : FGUEPOLStateInd
    }

def get_5guepol_msg_instances():
    return {k: FGUEPOLTypeClasses[k]() for k in FGUEPOLTypeClasses}
