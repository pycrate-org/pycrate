# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : test/test_mobile.py
# * Created : 2016-04-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii   import unhexlify
from timeit     import timeit

#from pycrate_core.elt               import Element
#Element._SAFE_STAT = False
#Element._SAFE_DYN  = False

from pycrate_mobile.GSMTAP          import *
from pycrate_mobile.NAS             import parse_NAS_MO, parse_NAS_MT, parse_NAS5G
from pycrate_mobile.SIGTRAN         import SIGTRAN
from pycrate_mobile.M3UA            import parse_M3UA
from pycrate_mobile.SCCP            import parse_SCCP
from pycrate_mobile.ISUP            import parse_ISUP
from pycrate_mobile.TS0960_GTPv0    import parse_GTPv0
from pycrate_mobile.TS29060_GTP     import parse_GTP
from pycrate_mobile.TS29281_GTPU    import parse_GTPU
from pycrate_mobile.TS29274_GTPC    import parse_GTPC
from pycrate_mobile.TS29244_PFCP    import parse_PFCP
from pycrate_diameter.Diameter      import DiameterGeneric
from pycrate_diameter.DiameterIETF  import DiameterIETF
from pycrate_diameter.Diameter3GPP  import Diameter3GPP
from pycrate_mobile.TS48006_BSSAP   import BSSAP
from pycrate_mobile.TS48008_BSSMAP  import BSSMAP
from pycrate_mobile.TS24501_IE      import (
    FGSID,
    FGSIDTYPE,
    FGSIDFMT,
    )
#
from pycrate_core.elt               import _with_json


# uplink messages
nas_pdu_mo = tuple(map(unhexlify, (
    # CS domain
    '05080200f11040005705f44c6a94c033035758a6', # MM LU Request
    '052401035758a605f4345b7129c2', # MM CM Service Request
    '0514a3c729e021042a92f637', # MM Auth Response
    '034504066004020005815e068160000000001502010040080402600400021f00', # CC Setup
    '8381', # CC Alert
    '834804066004020005811502010040080402600400021f00', # CC Call Confirmed
    '83c7', # CC Connect
    '03cf', # CC Connect Ack
    '036502e090', # CC Disconnect
    '032d', # CC Release
    '03aa', # CC Release Complete
    '8904', # SMS CP-ACK
    '890106020141020000', # SMS RP-ACK
    '19011c00020007913386094000f01001840a816000000000000004d4f29c0e', # SMS SUBMIT
    '0b7b1c14a11202010002013b300a04010f0405a3986c36027f0100', # SS Register
    '0bfa12a210020180300b02013c300604010f040131', # SS Facility
    '0baa', ## SS Release Complete
    # PS domain
    '080103e5e004010a0005f4fffa01f700f1104000100c0a53432b259ef989004000081705', # GMM Attach Request
    '0803', # GMM Attach Complete
    '08086002f8108003c81c1a53432b259ef9890040009dd9c633120080013a332c66240100026019e6e82017051805f4c2c85e9a3103e5e034320220005804e060c0401a05f4c3e0732f1b0602f8107500015d0100', # GMM RAU Request
    '081300224b1e647b290457a2f017', # GMM Auth Cipher Response
    '080a', # GMM RAU Complete
    '080c2605f4f1c8e8bf32022000', # GMM Service Request
    '8a49', # SM Modify PDP Ctxt Accept
    # EPS domain
    '17D2EBA20A020741020BF602F8107500E0C301732F04E060C04000240202D011D1271D8080211001000010810600000000830600000000000D00000A000010005C0A003103E5E0341302F810040511035758A65D0100C1', # EMM Attach Request
    '170d22f6f1030756080900000000000000', # EMM Ident Response
    '17450740e3040753083ec3a476f829b414', # EMM Auth Response
    '075e23093395684292874145f0', # EMM SMCompl
    '0202da2807066f72616e6765', # ESM Info Resp
    '074300035200c2', # EMM Attach Complete
    '0748610bf602f8108003c8c2e65e9a5804e060c0405202f810c4c25c0a00570220003103e5e0341302f810040511035758a65d0100c1', # EMM TAU Request
    'c7060500', # EMM Serv Request
    '074c6005f4c2e65e9a57022000', # EMM Ext Serv Request
    '074a', # EMM TAU Complete
    '07632009011d00010007913386094000f01101830a816000000000000005d4f29cae00', # EMM NAS transport + SMS CP-DATA
    '0745630bf602f8108003c8c2e65e9a', # EMM Detach Request MO
    '074d707800040200e86f6703091011570233c9d1' # EMM CP Service Request
    )))

# downlink messages
nas_pdu_mt = tuple(map(unhexlify, (
    '062e09006400634103022080', # RR Assignment Command
    # CS domain
    '051201f6e3c095753f23a9194291c86395f4782010a322f1689dc5000030dcb7d5eaafafe3', # MM Auth Request
    '0521', # MM CM Service Accept
    '050202f8100404', # MM LU Accept
    '83011e02e2a0', # CC Alert
    '8302', # CC Call Proceeding
    '83071e02e281', # CC Connect
    '030f', # CC Connect Ack
    '832502e090', # CC Disconnect
    '830302e2a0', # CC Progress
    '832d0802e090', # CC Release
    '032a0802e090', # CC Release Complete
    '03050401a05c0811833306000000f0', # CC Setup
    '090123010107913386094000f00017040b913306000000f000007101911172758004d4f29c0e', # SMS DELIVER
    '0904', # SMS CP-ACK
    '9901020302', # SMS RP-ACK
    '8b3a97a1819402018002013c30818b04010f048185c13a28867bc5602d180c0d8329866ff7fcdd6e17403a500c3d83b561b5b9c2181ed3ebf202885d06c164af584ca118a2dfe9797a3e2feb413a45ac472cd3c36936685e4fdbd3a0f1db3d7f2b64bde6db0d2acfe1e1715931ebc58e6fd00a1486c3cbecf96bda9c82d26cb60b14a381d4f239885c86d7d37350751a7c0dc3ee30390c92e58a', # SS Facility
    '8b3a9fa1819c02018102013c30819304010f04818dc4023d9c6683c86590fd4d979741f37ada9e068ddfeef91b047fd7e5209d22d60bc2e165f65c21eb4d9bd357b33955cc7a4937bd2c7797e9a0f65b9c669715b45e959e66a7e7653dc8fea6cbcba0b7d92c2f83c6ef76bb0c2abb414679d83d2e83c865783d3d07b14fc5bafc0d2f2b5aad96e25907e914b05ef3ed0695e7f0f0b8ac68b55a0a5c4f5aa6bfeb72', # SS Facility
    # PS domain
    '0802095e0102f8100405011805f4ffc856602a012c3801e0', # GMM Attach Accept
    '08120000211f12d433eac66f821ce2dfaf54c2c43b802810ac537cb6940c00006a1ec8ee4e0c7c8e', # GMM Auth Cipher Request
    '08214308804f79d87d2e838c4508804f79d87d2e838c4771019190727480490101', # GMM Information
    '081503', # GMM Ident Request
    '0809805e02f8100404011805f4d4cbf2852a012c320220003801e0', # GMM RAU Accept
    '0a4804030e1c921f7396d2fe7343ffff006400340101', # SM Modify PDP Ctxt Request
    # EPS domain
    '075501', # EMM Ident Request
    '075206905ADA1E7DA557ADA1E72650E21EE5E3104BFB73F6B4558000B1903AB88A27237F', # EMM Auth Request
    '37E8A14BCF00075D220605E060C04070C1', # EMM SMCmd
    '27807D6AA1016B8354', # EMM encrypted
    '0202d9', # ESM Info Req
    '07614308004f79d87d2e838c4508004f79d87d2e838c4771019190616180490101', # EMM Info
    '07420249062302f810c4c000725202c101081a066f72616e6765066d6e63303031066d6363323038046770727305010a7456415d010030101c911f7396fefe734bffff00fa00fa003203843401005e06fefedddd1010272780000d04c0a80a6e80210a0300000a8106c0a80a6e80210a0400000a83060000000000100205dc500bf602f8108003c8c2e65e9a1302f81004055949640103f05e0106', # EMM Attach Accept
    '0749015a4954062202f810c4a0570220001302f81004045949640103f05e0106', # EMM TAU Accept
    '0762028904', # EMM NAS transport + SMS CP-ACK
    '0746' # EMM Detach Accept
    )))

# 5G NAS pdu
nas_5g_pdu = tuple(map(unhexlify, (
    '7e004179000d0100f1100000000022222222222e02e0e0', # 5GMM Reg Req
    '7e0056000200002198a600000000000098a600000000000020105c717acfe29180001fb3117a0f18c3ab', # 5GMM Auth Req
    '7e00572d1034f95b9d3826fc095c9d9232f4d182c5', # 5GMM Auth Resp
    '7e038f2b564d007e005d010002e0e0', # 5GMM Sec Mode Cmd
    '7e0300000000007e005d000602f0f0e1360102', # 5GMM Sec Mode Cmd, more beefy
    '7e04fd5a6e42007e005e', # 5GMM Encrypted message
    '7e005e', # 5GMM Sec Mode Compl inner
    '7e005e7700091530014100002100f07100217e004169000d010302460fff000000000000f11001072e02f0f02f05040aabcdef', # 5GMM Sec Mode Compl inner, more beefy
    '7e004407', # 5GMM Reg Rej
    '7e0100000000037e004561000bf2030246010041c0e00010', # 5GMM Integ prot MO Dereg Req
    '7e0046', # 5GMM MO Dereg Accept
    '7e0042010177000bf2030246010041c0e000105407200302460000641505040aabcdef2101005e016516012c', # 5GMM Reg Accept
    '7e0043', # 5GMM Reg Compl
    '7e0054d0430989cef73a1d2696db6f450989cef73a1d2696db6f46694791501391446069490101', # 5GMM Config Upd Cmd
    '2e0501c1ffff91a1', # 5GSM PDU Sess Estab Req
    '2e0501c211000901000631310101ff0506060001060001290501ac115f012506056461746131', # 5GSM PDU Sess Estab Accept
    '7e00670100072e0602c1000091120681220401000001250706766973696f6e', # 5GMM UL Trans, 5GSM PDU Sess Estab Req
    '7e0100000000067e006801002d2e0602c2110009ff000631310101ff050603f42403f4242905010b000033220401000001250706766973696f6e1206', # 5GMM DL Trans, 5GSM PDU Sess Estab Accept
    '7e00670500020002', # UE policy complete
    )))


# SIGTRAN messages
sigtran_pdu = tuple(map(unhexlify, (
    '01000701000000d4000600080000000c011500080000000101020018000200008002000800000001800300080000000101160008000000010101000800000001011300080000000101140008000000010013000800000001011700080000000c010b0072626a4804000000106c62a16002010102012e3058840791198996909949820791198996000033044411330a8189961083993100a73ee8329bfd6681e8e8f41c949e83d4f5391d1406b1dfee73590ea297e774d03d4d4783e2f534bd0c0a83cce53be8fe9693e7a0b41b94a60300000000',
    )))

# M3UA messages (SIGTRAN supports them)
m3ua_pdu = tuple(map(unhexlify, (
    '01000301000000100011000800000001',
    '0100030400000008',
    '010004010000001c000b0008000000020006000c0000000100000002',
    '010004030000001c000b0008000000020006000c0000000100000002',
    '01000101000000740210006a0000012d000001360302000a0100003502020604c336018e0f4b001340470000060003400100000f40060062f2570001003a40080062f25700010001001040151405081162f25700013005f412f000003303301821004f40033500000056400562f2570001000000',
    '010001010000003402100023000000b9000000bb03000000090003070b0443bb00fe0443b900fe03000131000006000800000006',
    )))

# SCCP messages
sccp_pdu = tuple(map(unhexlify, (
    '09810305090242c804430a00981e651c480206f7490213b86c12a1100201020201183008800107a403800101', # SCCP Camel (wireshark)
    '090103070904430a00980242c81464124902ec0f6c0ca10a02010402011604028490',
    '090003050902420e04434324077ee27cc70461060390e874e972cf0101d102092ff26995033940018805011890002789048d2ad4fe8107394001011c30009f6204000000009f7b020c719f21021004840a0100210b403480000102820201049f5d090000210a33135009279f50090200210a33135009279f82170124bf82180c9f8215037d7b1f9f8219010f', # SCCP ANSI TCAP (wireshark)
    '090003050702c20102c20105018e560400', # SCCP SCMG (cloudshark)
    '090003070b04435604010443430a0105018e430a00',
    '098003101b0d120600710421435503483814710b120700120419530218522066626448046d5307026b1e281c060700118605010101a011600f80020780a1090607040000010001036c3ca13a0201000201023032040821431589431915f4810791195302185220040791195302185220a60880020780850205e0ad0a80086835613051868427', # SCCP UDT anonymized
    )))

# ISUP messages
isup_pdu = tuple(map(unhexlify, (
    'ad03010060010a00020a0884100081066153010a0884130061002099091d038090a3310200643f0884930031750740090801003a06430001ff0000390631d03ad03fc000', # ISUP Initial Address
    '6201060214012c01fb3601090c08849000811619290339042c90369000', # ISUP Address Complete
    '0b022c01011102163429010b00', # ISUP Call Progress
    '4c020901110202012d02006439022dc000', # ISUP Answer
    '7c020c0200028090', # ISUP Release
    'bf081000', # ISUP Release Complete
    )))

# GTPv0 messages
gtpv0_pdu = tuple(map(unhexlify, (
    '1e10008346830000ffffffff0001012143658759061b931f0e090ffc102d921126f8800002f1218300120573757065720361706e0767726f6c616e6484004080c0232301000023156d69636861656c2e6b61656c406e6577732e67726408746f746f3132333480211001000010810600000000830600000000000d000005008500040a141e288500040a141e2c860007919676688766f6', # CreatePDPCtxtReq
    '1e11004f468326f8ffffffff00010121436587590180061b931f08fe1000431100437f162f405b800006f121c0a8424384002280000d0408080808000d0408080404802110030000108106080808088306080804048500040a46505a8500040a46505a', # CreatePDPCtxtResp
    '1eff003000000043ffffffff000101214365875945000030004e0000ff06f6e4c0a84243c0a80101cd350050fcae3000000000007002400086550000020405b403030000', # GPDU
    )))


# GTPv1-C messages
gtp_pdu = tuple(map(unhexlify, (
    '3213003527c9b42e6a2400000180100102030411010203047f11223344850004750102038500047501020487000f020a921f7396ccfe9601ffff003600', # UpdatePDPCtxtRespGGSN
    '32120032be29401157c400000e05100908070611191817161405850004900102038500049001021387000f020a921f7396ccfe9601ffff003600', # UpdatePDPCtxtReqSGSN
    '3202000600000000f36e00000e20', # EchoResp
    '320100040000000000020000', # EchoReq
    '321500063aca3f774ee000000180', # DeletePDPCtxtResp
    '321400089fcf40346d80000013ff1405', # DeletePDPCtxtReq
    '321000e9000000006c7300000200010121436587f90e020ffd1020243e121139c016501405800002f121830020077465737461706e066d6e63303031066d63633030310467707273046770727384006c80c2231e0101001e1061626364616263646162636461626364554d54535f43484150c223340201003410656667686566676865666768656667686d6f62696c65406d792d746573742d677072732d6e6574776f726b2e636f6d80211001010010810600000000830600000000850004dc010203850004dc040506860007919989887767f687000f020a921f7396ccfe2201ffff0036009a00085307102030405060', # CreatePDPCtxtReq
    '3211005f12c839322e190000018008fe10a0b0c0d011a0b0c0d07f55667788800006f12164656667840018808021100301001081060101020283060101030300050101850004828384858500048283848587000f020a921f7396ccfe2201ffff003600b8000100', # CreatePDPCtxtResp
    )))

# GTPv1-U messages
gtpu_pdu = tuple(map(unhexlify, (
    '30ff003c04cec0bb4500003c22cb000080019bad0aa002ff481e268c0800995a0300b1016162636465666768696a6b6c6d6e6f7071727374757677616263646566676869', # GPDU (wireshark bug tracker)
    '361a00200000000000000040010868001004cec0bb85001022222222000000000000000000000002', # GTPU error ind
    '34ff0044008000350000008501100100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', # GTP-U GPDU UL header in 5G, with cleared payload
    '34ff003c00000001000000850100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', # GTP-U GPDU DL header in 5G, with cleared payload
    )))

# GTPv2-C messages
gtpc_pdu = tuple(map(unhexlify, (
    '482000c400000000000016000100080010214365871932f44c00050004930400004b000800538811500000000056000d001804f550000904f5500000001463000100015300030004f55052000100064d00040000080000570009008a000000070a010a0b570009018700000000c0a80169470005000461706e3180000100004f00050001000000004800080000003e8000003e807f00010000720002000a015f00020072315d001f0049000100055000160008090000000000000000000000000000000000000000', # Create Session Req (ngic project)
    '48220043eeffc000000017005d001200490001000557000900800c0000000b01016c570009008a000000070a010a0b56000d001804f550000904f550000000145300030004f550', # Modify Bearer Req (ngic project)
    '4844004deeffc00080001800490001000564000100025100150001000000abe0000000abe0000000abe0000000abe052000100065500190022208009100a989a81ffffffff108109100a989a81ffffffff', # Bearer Resource Cmd (ngic project)
    '48aa000d00000002000069008700010000', # Release Access Bearer Req (nextepc project)
    '4822002f0000000200006a0056000d001842f4700fca42f47000115a025d00120049000100055700090080000009610a554b32', # Modify Bearer Req (nextepc project)
    '482400260000000100006e00490001000556000d001842f470102342f47000ad7b024d00040008000000', # Delete Session Req (nextepc project)
    '482000b300000000000012000100080042041728114920f656000d001842f470102342f47000ad7b025300030042f47052000100065700090086800000097f0000024700090008696e7465726e657480000100fc63000100014f00050001000000007f000100004e00100080000a00000d00001000ff00031301845d002c0049000100055700090284000000120a554bd3500016004d0900000000000000000000000000000000000000007200020021005f0002005400', # Create Session Req (nextepc project)
    '48b00012000000020000130049000100059b00010061', # DL Data Notif (nextepc project)
    '485f0064000000010000020049000100055d0053004900010000540023002210010e301110ac160014ffffffff50c13321020e301110ac160014ffffffff50c1335700090081000000037f0000065000160008010000000041000000004100000000410000000041', # Create Bearer Req (open5gs project)
    '482000ec0012345601e240000100080000010189674523f14c00050011223344554b000800112233445566778856000d001800f110123400f110099887705300030000f1105200010006570009008612345678ac141e2847002300066d792d61706e08746573742d6d6e6f066d6e63303031066d63633030310467707273800001000163000100014f00050001000000007f000100004800080000100000001000004e001a008080211001000010810600000000830600000000000d00000a005d002c004900010005570009028444554455ac5a5046500016007c090000000000000000000000000000000000000000', #Create Session Req
    
    )))

# Diameter IETF and 3GPP messages
diam_pdu = tuple(map(unhexlify, (
    '010000c8800001010000000053cafe6a7dc0a11b00000108400000206f70656e6469616d2e6561702e746573746265642e61616100000128400000176561702e746573746265642e61616100000001014000000e0001c0a8692800000000010a4000000c000000000000010d000000154f70656e204469616d65746572000000000001164000000c4bed17dc000001094000000c00000000000001024000000c00000001000001024000000c000000050000010b0000000c000000010000012b4000000c00000000', # Cap Exchange Req (opendiameter project)
    '010000cc000001010000000053cafe6a7dc0a11b0000010c4000000c000007d1000001084000001a67772e6561702e746573746265642e616161000000000128400000176561702e746573746265642e61616100000001164000000c4bed163e000001014000000e0001c0a8691e00000000010a4000000c000000000000010d00000014667265654469616d657465720000010b0000000c000000640000012b4000000c00000000000001024000000c00000001000001034000000c00000003000001024000000c00000005', # Cap Exchange Resp (opendiameter project)
    '010001a8c000010c0000000500204a1663d000060000010740000046737570617574682e6561702e746573746265642e6161613b313237333832383932353b313b636c69656e743b67772e6561702e746573746265642e61616100000000011b400000176561702e746573746265642e61616100000001084000001f737570617574682e6561702e746573746265642e6161610000000128400000176561702e746573746265642e61616100000001024000000c00000005000001124000000c00000003000001984000000c00000001000001ce4000001302c6000b01636c69656e7400000000014000000e636c69656e740000000000044000000cc0a8690a000000204000001f737570617574682e6561702e746573746265642e61616100000000054000000c000000010000001e4000002730322d30302d30302d30302d30302d30303a6d616338303231312074657374000000001f4000001930322d30302d30302d30302d30312d30300000000000000c4000000c000005780000003d4000000c000000130000004d4000001e434f4e4e4543542035344d627073203830322e3131670000', # EAP Req (opendiameter project)
    '010001080000010c0000000500204a1663d000060000010740000046737570617574682e6561702e746573746265642e6161613b313237333832383932353b313b636c69656e743b67772e6561702e746573746265642e6161610000000001024000000c00000005000001124000000c000000030000010c4000000c000003e900000108400000206f70656e6469616d2e6561702e746573746265642e61616100000128400000176561702e746573746265642e61616100000000014000000e636c69656e740000000001ce4000000e01c700060d200000000001234000000c00000168000001144000000c0000001e000001154000000c000000010000001b0000000c00000bb8', # EAP Resp (opendiameter project)
    '010000588000011a0000000000204a1967700003000001084000001f6261636b656e642e6561702e746573746265642e6161610000000128400000176561702e746573746265642e61616100000001114000000c00000000', # Discon-peer Req (opendiameter project)
    '010000540000011a0000000000204a1967700003000001084000001a67772e6561702e746573746265642e616161000000000128400000176561702e746573746265642e616161000000010c4000000c000007d1', # Discon-peer Ans (opendiameter project)
    '01000108c000013c010000230dde9cba8415e2e9000001074000002d6d6d652e6c6f63616c646f6d61696e3b313536303935303834393b31383b6170705f733661000000000001154000000c0000000100000108400000176d6d652e6c6f63616c646f6d61696e0000000128400000136c6f63616c646f6d61696e000000011b400000136c6f63616c646f6d61696e000000000140000017323434303731383231313934303236000000040880000010000028af000003ec0000057dc0000010000028af000000020000057fc000000f000028af42f470000000064f80000010000028af0000000000000104400000200000010a4000000c000028af000001024000000c01000023', # ULR (nextepc project)
    '010003104000013c010000230dde9cba8415e2e9000001074000002d6d6d652e6c6f63616c646f6d61696e3b313536303935303834393b31383b6170705f73366100000000000108400000176873732e6c6f63616c646f6d61696e0000000128400000136c6f63616c646f6d61696e000000010c4000000c000007d1000001154000000c000000010000057ec0000010000028af0000000100000578c0000248000028af00000592c0000010000028af0000002000000590c0000010000028af0000000000000589c0000010000028af000000020000059bc000002c000028af00000204c0000010000028af3e80000000000203c0000010000028af3e80000000000595c00001e0000028af0000058fc0000010000028af0000000100000594c0000010000028af0000000000000596c0000090000028af0000058fc0000010000028af00000001000005b0c0000010000028af00000002000001ed4000000c6970747600000597c0000058000028af00000404c0000010000028af000000060000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af0000000100000596c0000090000028af0000058fc0000010000028af00000002000005b0c0000010000028af00000002000001ed4000000c766f697000000597c0000058000028af00000404c0000010000028af000000050000040a8000003c000028af0000041680000010000028af000000020000041780000010000028af000000010000041880000010000028af0000000100000596c0000094000028af0000058fc0000010000028af00000003000005b0c0000010000028af00000002000001ed40000010696e7465726e657400000597c0000058000028af00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000030000041780000010000028af000000010000041880000010000028af000000010000065380000010000028af000002d000000104400000200000010a4000000c000028af000001024000000c01000023', # ULA (nextepc project)
    '01000104c000013e010000230dde9cb98415e2e8000001074000002d6d6d652e6c6f63616c646f6d61696e3b313536303935303834393b31373b6170705f733661000000000001154000000c0000000100000108400000176d6d652e6c6f63616c646f6d61696e0000000128400000136c6f63616c646f6d61696e000000011b400000136c6f63616c646f6d61696e0000000001400000173234343037313832313139343032360000000580c000002c000028af00000582c0000010000028af0000000100000584c0000010000028af000000010000057fc000000f000028af42f4700000000104400000200000010a4000000c000028af000001024000000c01000023', # AIR (nextepc project)
    '010001384000013e010000230dde9cb98415e2e8000001074000002d6d6d652e6c6f63616c646f6d61696e3b313536303935303834393b31373b6170705f73366100000000000585c0000090000028af00000586c0000084000028af000005a7c000001c000028af1bfb50b4ccdade9bc64c0e79a48c52ae000005a8c0000014000028afee84e634eb3b2d25000005a9c000001c000028af738dfd83971680003f2c75b0b8c3ff6c000005aac000002c000028af7fedfc639da901b42de6c7dea5f1867568d5e0a264b4c2e2915fd5b0a376122e00000108400000176873732e6c6f63616c646f6d61696e0000000128400000136c6f63616c646f6d61696e000000010c4000000c000007d1000001154000000c0000000100000104400000200000010a4000000c000028af000001024000000c01000023', # AIA (nextepc project)
    )))

# PFCP messages
pfcp_pdu = tuple(map(unhexlify, (
    # PFCP Heartbeat (open5gs)
    '2401000c0000bd0000600004e42eaecf',
    '2002000c00007c0000600004e42eaecf',
    # PFCP Assoc Setup (open5gs)
    '2005001a00000100003c000500c0a8386900600004e4296d960059000100',
    '2006009b00000100003c00050203757067001300010100600004e4296caa002b00060001000000000074000f2900ac10000108696e7465726e65748002006048f9767070207632312e30312e302d31337e67656565386361393037206275696c742062792074726176656c70696e67206f6e2074726176656c70696e672d5669727475616c426f7820617420323032312d30342d31335431393a30393a3337',
    '2005001b00000300003c000500c0a814fa00600004e367dc2d002b00021001',
    '2006001a00000300003c000500c0a81403001300010100600004e367dc46',
    # PFCP Sess Estab (open5gs)
    '2132006e000000000000000000000100003c000500c0a814030039000d020000000000002710c0a8140300010029003800020001001d0004000003e80002000a00140001030015000105005f000100006c00040000000100030017006c000400000001002c0002020000040005002a000100',
    '2133001a0000000000000000000001000013000141003c0005000a0b0c0d',
    # PFCP Sess Mod (open5gs)
    '2134014b00000000000000010000030000010068003800020005001d0004000000050002004600140001010016000908696e7465726e6574001700300100002c7065726d6974206f7574207564702066726f6d203137322e32322e302e323020343934353920746f20616e79006c000400000004006d00040000000200010072003800020006001d0004000000060002004b001400010000150001040016000908696e7465726e6574001700300100002c7065726d6974206f7574207564702066726f6d203137322e32322e302e323020343934353920746f20616e79005f000100006c000400000005006d00040000000200030012006c000400000004002c00010c005800010100030016006c000400000005002c00010200040005002a00010100070029006d0004000000020019000100001a000a00000000410000000041001b000a00000000410000000041',
    '21350032000000000000000100000300001300010100080006003800020005000800130038000200060015000901000000067f000007'
    )))

# BSSAP and BSSMAP
bssap_pdu = tuple(map(unhexlify, (
    '000430040120', # BSSAP Mgmt / BSSMAP Reset
    '000131', # BSSAP Mgmt / BSSMAP Reset Ack
    '01033009012d010007914477581006500021400491832000002221919012254014050003070101dc69771130380402eeb43b0d', # BSSAP DT / SMS
    # from #osmocom
    '001f5705080052f010184c1c19170f05081052f010184e5305f4506613c97d0180', # BSSAP Mgmt / BSSMAP LUR
    '01000e050252f010184c1705f433c765f6', # BSSAP Mgmt / BSSMAP LUA
    '010003051803', # BSSAP DT / NAS
    '000420040109', # BSSAP Mgmt / BSSMAP Clear cmd
    '000121', # BSSAP Mgmt / BSSMAP Clear compl
    )))


def test_nas_mo(nas_pdu=nas_pdu_mo):
    for pdu in nas_pdu:
        m, e = parse_NAS_MO(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_nas_mt(nas_pdu=nas_pdu_mt):
    for pdu in nas_pdu:
        m, e = parse_NAS_MT(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_nas_5g(nas_pdu=nas_5g_pdu):
    for pdu in nas_pdu:
        m, e = parse_NAS5G(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


fgsid_vals = (
    {'Type': FGSIDTYPE.NO},
    {'Type': FGSIDTYPE.SUPI, 'Fmt': FGSIDFMT.IMSI, 'Value': {'PLMN': '20869', 'RoutingInd': '1234', 'Output': '1234567890'}},
    {'Type': FGSIDTYPE.SUPI, 'Fmt': FGSIDFMT.NSI, 'Value': 'type1.rid1234.schid0.useridusername@realm'},
    {'Type': FGSIDTYPE.GUTI, 'PLMN': '20869', 'AMFRegionID': 0xaa, 'AMFSetID': 0x200, 'AMFPtr': 0x1f, '5GTMSI': 0x11223344},
    {'Type': FGSIDTYPE.IMEI, 'Digits': '012345678901234'},
    {'Type': FGSIDTYPE.STMSI, 'AMFSetID': 0x200, 'AMFPtr': 0x1f, '5GTMSI': 0x11223344},
    {'Type': FGSIDTYPE.IMEISV, 'Digits': '01234567890123401'},
    {'Type': FGSIDTYPE.MAC, 'MAURI': 0, 'MAC': b'\x0a\x00\x27\x00\x00\x00'},
    {'Type': FGSIDTYPE.EUI64, 'EUI64': 8*b'\xaa'}
    )

def test_5gsid(vals=fgsid_vals):
    for val in vals:
        ident = FGSID(val=val)
        buf = ident.to_bytes()
        val = ident.get_val()
        typ, dec = ident.decode()
        ident = FGSID()
        ident.from_bytes(buf)
        assert(ident.decode() == (typ, dec))
        ident = FGSID()
        ident.encode(typ, dec)
        assert(ident.to_bytes() == buf)
        ident = FGSID(val=val)
        assert(ident.to_bytes() == buf)


def test_sigtran(sigtran_pdu=sigtran_pdu + m3ua_pdu):
    for pdu in sigtran_pdu:
        S = SIGTRAN()
        S.from_bytes(pdu)
        v = S.get_val()
        S.reautomate()
        assert( S.get_val() == v )
        S.__init__()
        S.set_val(v)
        assert( S.to_bytes() == pdu )
        #
        if _with_json:
            t = S.to_json()
            S.from_json(t)
            assert( S.get_val() == v )


def test_m3ua(m3ua_pdu=m3ua_pdu):
    for pdu in m3ua_pdu:
        m, e = parse_M3UA(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.__init__()
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_sccp(sccp_pdu=sccp_pdu):
    for pdu in sccp_pdu:
        m, e = parse_SCCP(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        #m.__init__()
        m.set_val(v)
        assert( m.to_bytes() == pdu)
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )
    #
    # verify GT specific methods
    m, e = parse_SCCP(sccp_pdu[5])
    m.reautomate()
    called  = m[3].get_gt().get_addr()
    calling = m[4].get_gt().get_addr()
    m[3].get_gt().set_addr_bcd(called)
    m[4].get_gt().set_addr_bcd(calling)
    assert( m[3].get_gt().get_addr() == called )
    assert( m[4].get_gt().get_addr() == calling )


def test_isup(isup_pdu=isup_pdu):
    for pdu in isup_pdu:
        m, e = parse_ISUP(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        #m.__init__()
        m.set_val(v)
        assert( m.to_bytes() == pdu)
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_gtpv0(gtp_pdu=gtpv0_pdu):
    for pdu in gtp_pdu:
        m, e = parse_GTPv0(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_gtp(gtp_pdu=gtp_pdu):
    for pdu in gtp_pdu:
        m, e = parse_GTP(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_gtpu(gtpu_pdu=gtpu_pdu):
    for pdu in gtpu_pdu:
        m, e = parse_GTPU(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_gtpc(gtpc_pdu=gtpc_pdu):
    for pdu in gtpc_pdu:
        m, e = parse_GTPC(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_diameter(diam_pdu=diam_pdu):
    for dm in (DiameterGeneric(), DiameterIETF(), Diameter3GPP()):
        for pdu in diam_pdu:
            dm.from_bytes(pdu)
            v = dm.get_val()
            dm.reautomate()
            assert( dm.get_val() == v )
            dm.__init__()
            dm.set_val(v)
            assert( dm.to_bytes() == pdu )
            #
            if _with_json:
                t = dm.to_json()
                dm.from_json(t)
                assert( dm.get_val() == v )


def test_pfcp(pfcp_pdu=pfcp_pdu):
    for pdu in pfcp_pdu:
        m, e = parse_PFCP(pdu)
        assert( e == 0 )
        v = m.get_val()
        m.reautomate()
        assert( m.get_val() == v )
        m.set_val(v)
        assert( m.to_bytes() == pdu )
        #
        if _with_json:
            t = m.to_json()
            m.from_json(t)
            assert( m.get_val() == v )


def test_bssap(bssap_pdu=bssap_pdu):
    
    bm = BSSMAP()
    for pdu in bssap_pdu:
        B = BSSAP()
        B.from_bytes(pdu)
        v = B.get_val()
        B.reautomate()
        assert( B.get_val() == v )
        B.__init__()
        B.set_val(v)
        assert( B.to_bytes() == pdu )
        #
        if _with_json:
            t = B.to_json()
            B.from_json(t)
            assert( B.get_val() == v )
        #
        if B['DistributionUnit']['Discrimination'].get_val() == 0:
            # BSSMAP
            pdu = B['L3'].get_val()
            BM = BSSMAP()
            BM.from_bytes(pdu)
            v = BM.get_val()
            BM.reautomate()
            assert( BM.get_val() == v )
            BM.__init__()
            BM.set_val(v)
            assert( BM.to_bytes() == pdu )
            #
            if _with_json:
                t = BM.to_json()
                BM.from_json(t)
                assert( BM.get_val() == v )


def test_perf_mobile():
    
    print('[+] NAS MO decoding and re-encoding')
    Ta = timeit(test_nas_mo, number=20)
    print('test_nas_mo: {0:.4f}'.format(Ta))
    
    print('[+] NAS MT decoding and re-encoding')
    Tb = timeit(test_nas_mt, number=30)
    print('test_nas_mt: {0:.4f}'.format(Tb))
    
    print('[+] NAS 5G decoding and re-encoding')
    Tc = timeit(test_nas_5g, number=40)
    print('test_nas_5g: {0:.4f}'.format(Tc))
    
    print('[+] 5GSID decoding and re-encoding')
    Tl = timeit(test_5gsid, number=300)
    print('test_5gsid: {0:.4f}'.format(Tl))
    
    print('[+] SIGTRAN decoding and re-encoding')
    Td = timeit(test_sigtran, number=250)
    print('test_sigtran: {0:.4f}'.format(Td))
    
    print('[+] M3UA decoding and re-encoding')
    Tm = timeit(test_m3ua, number=250)
    print('test_m3ua: {0:.4f}'.format(Tm))
    
    print('[+] SCCP decoding and re-encoding')
    Te = timeit(test_sccp, number=150)
    print('test_sccp: {0:.4f}'.format(Te))
    
    print('[+] ISUP decoding and re-encoding')
    Tj = timeit(test_isup, number=60)
    print('test_isup: {0:.4f}'.format(Tj))
    
    print('[+] GTPv0 decoding and re-encoding')
    Tl = timeit(test_gtpv0, number=200)
    print('test_gtpv0: {0:.4f}'.format(Tl))
    
    print('[+] GTPv1-C decoding and re-encoding')
    Tk = timeit(test_gtp, number=60)
    print('test_gtp: {0:.4f}'.format(Tk))
    
    print('[+] GTP-U decoding and re-encoding')
    Tf = timeit(test_gtpu, number=300)
    print('test_gtpu: {0:.4f}'.format(Tf))
    
    print('[+] GTPv2-C decoding and re-encoding')
    Tg = timeit(test_gtpc, number=25)
    print('test_gtpc: {0:.4f}'.format(Tg))
    
    print('[+] Diameter decoding and re-encoding')
    Th = timeit(test_diameter, number=8)
    print('test_diameter: {0:.4f}'.format(Th))
    
    print('[+] PFCP decoding and re-encoding')
    Ti = timeit(test_pfcp, number=50)
    print('test_pfcp: {0:.4f}'.format(Ti))
    
    print('[+] BSSAP / BSSMAP decoding / re-encoding')
    Tn = timeit(test_bssap, number=200)
    print('test_bssap: {0:.4f}'.format(Tn))
    
    print('[+] test_mobile total time: {0:.4f}'.format(Ta+Tb+Tc+Td+Te+Tf+Tg+Th+Ti+Tj+Tk+Tl+Tm+Tn))


if __name__ == '__main__':
    test_perf_mobile()

