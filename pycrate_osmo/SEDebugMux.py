# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Vadim Yanitskiy
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
# * File Name : pycrate_osmo/SEDebugMux.py
# * Created : 2022-01-08
# * Authors : Vadim Yanitskiy
# *--------------------------------------------------------
#*/

import enum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *


class PascalString(Envelope):
    ''' A variable length string that is prefixed by a length field '''
    _GEN = (
        Uint8('L', desc='Length'),
        Buf('V', desc='Value')
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['L'].set_valauto(lambda: self['V'].get_bl() >> 3)
        self['V'].set_blauto(lambda: self['L'].get_val() << 3)

class DebugMuxMsgType(enum.Enum):
    ''' DebugMux message type '''
    Enquiry             = 0x65 # 'e'
    Ident               = 0x66 # 'f'
    Ping                = 0x67 # 'g'
    Pong                = 0x68 # 'h'

    DPAnnounce          = 0x69 # 'i'
    # TODO              = 0x6a # 'j'
    ConnEstablish       = 0x6b # 'k'
    ConnEstablished     = 0x6c # 'l'
    ConnTerminate       = 0x6d # 'm'
    ConnTerminated      = 0x6e # 'n'
    ConnData            = 0x6f # 'o'
    # TODO:             = 0x70 # 'p'
    Ack                 = 0x71 # 'q'

DebugMuxMsgType_dict = { e.value : e.name for e in DebugMuxMsgType }

class DebugMuxMsg(Alt):
    ''' DebugMux message, may be contained in a DebugMuxFrame '''
    class Ident(Envelope):
        ''' DebugMuxMsgType.Ident structure '''
        _GEN = (
            Uint32LE('TargetId'),
            PascalString('Ident'),
            )

    class PingPong(PascalString):
        ''' DebugMuxMsgType.{Ping,Pong} structure '''

    class DPAnnounce(Envelope):
        ''' DebugMuxMsgType.DPAnnounce structure '''
        _GEN = (
            Uint16LE('DPRef'),
            PascalString('Name'),
            )

    class ConnEstablish(Envelope):
        ''' DebugMuxMsgType.ConnEstablish structure '''
        _GEN = (
            Uint16LE('DPRef'),
            )

    class ConnEstablished(Envelope):
        ''' DebugMuxMsgType.ConnEstablished structure '''
        _GEN = (
            Uint16LE('DPRef'),
            Uint16LE('ConnRef'),
            Uint16LE('DataBlockLimit'),
            )

    class ConnTerminate(Envelope):
        ''' DebugMuxMsgType.ConnTerminate structure '''
        _GEN = (
            Uint16LE('ConnRef'),
            )

    class ConnTerminated(Envelope):
        ''' DebugMuxMsgType.ConnTerminated structure '''
        _GEN = (
            Uint16LE('DPRef'),
            Uint16LE('ConnRef'),
            )

    class ConnData(Envelope):
        ''' DebugMuxMsgType.ConnData structure '''
        _GEN = (
            Uint16LE('ConnRef'),
            BufAuto('Data'),
            )

    # All currently known messages
    _GEN = {
        DebugMuxMsgType.Ident.value              : Ident(),
        DebugMuxMsgType.Ping.value               : PingPong(),
        DebugMuxMsgType.Pong.value               : PingPong(),
        DebugMuxMsgType.DPAnnounce.value         : DPAnnounce(),
        DebugMuxMsgType.ConnEstablish.value      : ConnEstablish(),
        DebugMuxMsgType.ConnEstablished.value    : ConnEstablished(),
        DebugMuxMsgType.ConnTerminate.value      : ConnTerminate(),
        DebugMuxMsgType.ConnTerminated.value     : ConnTerminated(),
        DebugMuxMsgType.ConnData.value           : ConnData(),
        }

class DebugMuxFrame(Envelope):
    ''' DebugMux frame, may contain a DebugMuxMsg '''
    _GEN = (
        Buf('Magic', desc='Start marker', val=b'\x42\x42', bl=16),
        Uint16LE('Length', desc='Message length'), # val automated
        Uint8('TxCount', desc='Number of messages sent'),
        Uint8('RxCount', desc='Number of messages received'),
        Uint8('MsgType', desc='Message type', dic=DebugMuxMsgType_dict),
        DebugMuxMsg('MsgData', sel=lambda self: self.get_env()['MsgType'].get_val()),
        Uint16LE('FCS', desc='Frame Check Sequence', rep=REPR_HEX) # val automated
        )

    # Kudos to Stefan @Sec Zehl for finding the CRC function parameters
    # crcmod.mkCrcFun(0x11021, rev=True, initCrc=0x0, xorOut=0xffff)
    FCS16Lookup = [
        0x0000,0x1189,0x2312,0x329B,0x4624,0x57AD,0x6536,0x74BF,
        0x8C48,0x9DC1,0xAF5A,0xBED3,0xCA6C,0xDBE5,0xE97E,0xF8F7,
        0x1081,0x0108,0x3393,0x221A,0x56A5,0x472C,0x75B7,0x643E,
        0x9CC9,0x8D40,0xBFDB,0xAE52,0xDAED,0xCB64,0xF9FF,0xE876,
        0x2102,0x308B,0x0210,0x1399,0x6726,0x76AF,0x4434,0x55BD,
        0xAD4A,0xBCC3,0x8E58,0x9FD1,0xEB6E,0xFAE7,0xC87C,0xD9F5,
        0x3183,0x200A,0x1291,0x0318,0x77A7,0x662E,0x54B5,0x453C,
        0xBDCB,0xAC42,0x9ED9,0x8F50,0xFBEF,0xEA66,0xD8FD,0xC974,
        0x4204,0x538D,0x6116,0x709F,0x0420,0x15A9,0x2732,0x36BB,
        0xCE4C,0xDFC5,0xED5E,0xFCD7,0x8868,0x99E1,0xAB7A,0xBAF3,
        0x5285,0x430C,0x7197,0x601E,0x14A1,0x0528,0x37B3,0x263A,
        0xDECD,0xCF44,0xFDDF,0xEC56,0x98E9,0x8960,0xBBFB,0xAA72,
        0x6306,0x728F,0x4014,0x519D,0x2522,0x34AB,0x0630,0x17B9,
        0xEF4E,0xFEC7,0xCC5C,0xDDD5,0xA96A,0xB8E3,0x8A78,0x9BF1,
        0x7387,0x620E,0x5095,0x411C,0x35A3,0x242A,0x16B1,0x0738,
        0xFFCF,0xEE46,0xDCDD,0xCD54,0xB9EB,0xA862,0x9AF9,0x8B70,
        0x8408,0x9581,0xA71A,0xB693,0xC22C,0xD3A5,0xE13E,0xF0B7,
        0x0840,0x19C9,0x2B52,0x3ADB,0x4E64,0x5FED,0x6D76,0x7CFF,
        0x9489,0x8500,0xB79B,0xA612,0xD2AD,0xC324,0xF1BF,0xE036,
        0x18C1,0x0948,0x3BD3,0x2A5A,0x5EE5,0x4F6C,0x7DF7,0x6C7E,
        0xA50A,0xB483,0x8618,0x9791,0xE32E,0xF2A7,0xC03C,0xD1B5,
        0x2942,0x38CB,0x0A50,0x1BD9,0x6F66,0x7EEF,0x4C74,0x5DFD,
        0xB58B,0xA402,0x9699,0x8710,0xF3AF,0xE226,0xD0BD,0xC134,
        0x39C3,0x284A,0x1AD1,0x0B58,0x7FE7,0x6E6E,0x5CF5,0x4D7C,
        0xC60C,0xD785,0xE51E,0xF497,0x8028,0x91A1,0xA33A,0xB2B3,
        0x4A44,0x5BCD,0x6956,0x78DF,0x0C60,0x1DE9,0x2F72,0x3EFB,
        0xD68D,0xC704,0xF59F,0xE416,0x90A9,0x8120,0xB3BB,0xA232,
        0x5AC5,0x4B4C,0x79D7,0x685E,0x1CE1,0x0D68,0x3FF3,0x2E7A,
        0xE70E,0xF687,0xC41C,0xD595,0xA12A,0xB0A3,0x8238,0x93B1,
        0x6B46,0x7ACF,0x4854,0x59DD,0x2D62,0x3CEB,0x0E70,0x1FF9,
        0xF78F,0xE606,0xD49D,0xC514,0xB1AB,0xA022,0x92B9,0x8330,
        0x7BC7,0x6A4E,0x58D5,0x495C,0x3DE3,0x2C6A,0x1EF1,0x0F78,
    ]

    @classmethod
    def _fcs_func(cls, data):
        ''' Calculate an FCS for the give data bytes '''
        crc = 0xffff
        for val in data:
            idx = val ^ (crc & 0xff)
            crc = cls.FCS16Lookup[idx] ^ (crc >> 8)
        return crc ^ 0xffff

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        
        # The 'Length' field indicates length of *all* fields following it
        self['Length'].set_valauto(lambda: 3 + self['MsgData'].get_len() + 2)
        self['MsgData'].set_blauto(lambda: (self['Length'].get_val() - 3 - 2) * 8)
        self['FCS'].set_valauto(lambda: self._fcs_func(self[:-1].to_bytes()))
