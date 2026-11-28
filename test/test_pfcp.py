"""PFCP field-layout regressions using synthetic TS 29.244 wire values."""

import unittest

from pycrate_core.base import Buf
from pycrate_core.utils import PycrateErr
from pycrate_mobile import TS29244_PFCP as P


class TestPFCPFieldLayouts(unittest.TestCase):
    @staticmethod
    def ie(typ, data):
        return typ.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data

    def message(self, typ, data):
        unknown = self.ie(32767, b'\xaa\xbb')
        if typ == 72:
            payload = self.ie(13, self.ie(81, b'\0\0\0\1') + data + unknown)
            msg_type, session = 52, True
        elif typ == 98:
            payload = self.ie(10, self.ie(108, b'\0\0\0\1')
                              + self.ie(11, data + unknown))
            msg_type, session = 52, True
        elif typ == 192:
            payload = self.ie(96, b'\0\0\0\x3c') + data + unknown
            msg_type, session = 1, False
        else:
            payload = (self.ie(60, b'\0\xc0\0\2\1')
                       + self.ie(96, b'\0\0\0\x3c')
                       + self.ie(233, self.ie(177, b'\0\1p') + data + unknown))
            msg_type, session = 5, False
        header = (b'\x21' if session else b'\x20') + bytes([msg_type])
        tail = (b'\0' * 8 if session else b'') + b'\0\0\1\0'
        return header + (len(tail) + len(payload)).to_bytes(2, 'big') + tail + payload

    def find_ie(self, ies, typ):
        for ie in ies:
            if ie[0].get_val() == typ:
                return ie[3]
            if isinstance(ie[3], P.PFCPIEs):
                found = self.find_ie(ie[3], typ)
                if found is not None:
                    return found
        return None

    def check_wire(self, typ, data, cls, expected):
        value = cls()
        value.from_bytes(data)
        self.assertEqual(value.to_bytes(), data)
        for name, val in expected.items():
            self.assertEqual(value[name].get_val(), val)
        built = cls()
        built.set_val(value.get_val())
        self.assertEqual(built.to_bytes(), data)
        wire = self.ie(typ, data)
        ie = P.PFCPIE()
        ie.from_bytes(wire)
        self.assertIsInstance(ie[3], cls)
        self.assertEqual(ie.to_bytes(), wire)
        outer = self.message(typ, wire)
        message, error = P.parse_PFCP(outer)
        self.assertEqual(error, 0)
        typed = self.find_ie(message[1], typ)
        self.assertIsInstance(typed, cls)
        for name, val in expected.items():
            self.assertEqual(typed[name].get_val(), val)
        self.assertEqual(self.find_ie(message[1], 32767).get_val(), b'\xaa\xbb')
        self.assertEqual(message.to_bytes(), outer)

    def test_dropped_dl_traffic_threshold(self):
        for flags in range(4):
            for count in (0, 5, (1 << 64) - 1):
                with self.subTest(flags=flags, count=count):
                    data = bytes([flags])
                    expected = {'DLPA': flags & 1, 'DLBY': flags >> 1}
                    if flags & 1:
                        data += count.to_bytes(8, 'big')
                        expected['DLPackets'] = count
                    if flags & 2:
                        data += count.to_bytes(8, 'big')
                        expected['NumBytesDLData'] = count
                    data += b'\xab\xcd'
                    self.check_wire(72, data, P.DroppedDLTrafficThreshold, expected)

    def test_header_enrichment(self):
        for name, value in ((b'x-test', b''), (b'abc', b'xy'),
                            (b'x' * 255, b'v' * 255)):
            with self.subTest(name_size=len(name), value_size=len(value)):
                data = (b'\0' + bytes([len(name)]) + name
                        + bytes([len(value)]) + value + b'\xab\xcd')
                self.check_wire(98, data, P.HeaderEnrichment, {})
                decoded = P.HeaderEnrichment()
                decoded.from_bytes(data)
                self.assertEqual(decoded['HeaderFieldName']['Val'].get_val(), name)
                self.assertEqual(decoded['HeaderFieldValue']['Val'].get_val(), value)

    def test_source_ip_address(self):
        ipv4, ipv6 = b'\xc0\0\2\1', bytes.fromhex('20010db8000000000000000000000001')
        for family in (1, 2, 3):
            for mask in (False, True):
                with self.subTest(family=family, mask=mask):
                    flags = family | (4 if mask else 0)
                    data = bytes([flags]) + (ipv4 if family & 2 else b'')
                    data += ipv6 if family & 1 else b''
                    data += b'\x18' if mask else b''
                    data += b'\xab\xcd'
                    expected = {'MPL': int(mask), 'V4': (family >> 1) & 1,
                                'V6': family & 1, 'ext': b'\xab\xcd'}
                    if mask:
                        expected['MaskPrefLen'] = 24
                    self.check_wire(192, data, P.SourceIPAddress, expected)

    def test_ip_version(self):
        for flags in (1, 2, 3, 0xfd, 0xfe, 0xff):
            with self.subTest(flags=flags):
                self.check_wire(258, bytes([flags]) + b'\xab\xcd', P.IPversion,
                                {'V4': flags & 1, 'V6': (flags >> 1) & 1,
                                 'spare': flags >> 2, 'ext': b'\xab\xcd'})

    def test_vlan_tags(self):
        # TS 29.244 8.2.94 / 8.2.95: octet 6 = VID MSB (4 bits), DEI flag (1 bit),
        # PCP value (3 bits); octet 7 = VID LSB
        for typ, cls in ((134, P.CTAG), (135, P.STAG)):
            for pcp, dei, vid in ((0, 0, 0), (5, 1, 0x123), (7, 1, 0xfff)):
                with self.subTest(cls=cls.__name__, pcp=pcp, dei=dei, vid=vid):
                    data = bytes([0x07, (vid >> 8) << 4 | dei << 3 | pcp, vid & 0xff])
                    value = cls()
                    value.from_bytes(data)
                    self.assertEqual(value['PCPValue'].get_val(), pcp)
                    self.assertEqual(value['DEIFlag'].get_val(), dei)
                    self.assertEqual(value['CVID_MSB'].get_val(), vid >> 8)
                    self.assertEqual(value['CVID_LSB'].get_val(), vid & 0xff)
                    self.assertEqual(value.to_bytes(), data)
                    wire = self.ie(typ, data)
                    ie = P.PFCPIE()
                    ie.from_bytes(wire)
                    self.assertIsInstance(ie[3], cls)
                    self.assertEqual(ie.to_bytes(), wire)

    def test_message_priority_labels(self):
        # TS 29.244 7.2.2.4.1: 0 is the highest priority, 15 the lowest
        for prio, label in ((0, 'highest priority'), (15, 'lowest priority')):
            with self.subTest(prio=prio):
                data = (bytes([0x22, 0x01, 0x00, 0x0c, 0, 0, 1, prio << 4])
                        + self.ie(96, b'\0\0\0\x3c'))
                message, error = P.parse_PFCP(data)
                self.assertEqual(error, 0)
                field = message[0]['MPSel'].get_alt()['MsgPriority']
                self.assertEqual(field.get_val(), prio)
                self.assertIn(label, field.repr())
                self.assertEqual(message.to_bytes(), data)

    def test_flag_changes_on_retained_objects(self):
        threshold = P.DroppedDLTrafficThreshold()
        threshold.from_bytes(b'\x03' + (5).to_bytes(8, 'big') * 2 + b'\xab')
        threshold['DLPA'].set_val(0)
        self.assertEqual(threshold.to_bytes(), b'\x02' + (5).to_bytes(8, 'big') + b'\xab')
        threshold['DLBY'].set_val(0)
        self.assertEqual(threshold.to_bytes(), b'\x00\xab')
        threshold['DLPA'].set_val(1)
        self.assertEqual(threshold.to_bytes(), b'\x01' + (5).to_bytes(8, 'big') + b'\xab')
        source = P.SourceIPAddress()
        source.from_bytes(b'\x06\xc0\0\2\1\x18\xab')
        source['MPL'].set_val(0)
        self.assertEqual(source.to_bytes(), b'\x02\xc0\0\2\1\xab')
        source['MPL'].set_val(1)
        self.assertEqual(source.to_bytes(), b'\x06\xc0\0\2\1\x18\xab')

    def test_truncated_values_keep_raw_ie_fallback(self):
        cases = ((72, P.DroppedDLTrafficThreshold, b'\x01' + b'\0' * 7),
                 (72, P.DroppedDLTrafficThreshold, b'\x02' + b'\0' * 7),
                 (98, P.HeaderEnrichment, b'\0\x03ab'),
                 (98, P.HeaderEnrichment, b'\0\x01x\x02v'),
                 (192, P.SourceIPAddress, b'\x06\xc0\0\2\1'),
                 (192, P.SourceIPAddress, b'\x01' + b'\0' * 15),
                 (258, P.IPversion, b''))
        for typ, cls, data in cases:
            with self.subTest(typ=typ, data=data):
                with self.assertRaises(PycrateErr):
                    cls().from_bytes(data)
                wire = self.ie(typ, data)
                ie = P.PFCPIE()
                ie.from_bytes(wire)
                self.assertIsInstance(ie[3], Buf)
                self.assertEqual(ie[3].get_val(), data)
                self.assertEqual(ie.to_bytes(), wire)
                if typ != 192:
                    outer = self.message(typ, wire)
                    message, error = P.parse_PFCP(outer)
                    self.assertEqual(error, 0)
                    self.assertIsInstance(self.find_ie(message[1], typ), Buf)
                    self.assertEqual(message.to_bytes(), outer)
                valid = {72: b'\x03' + b'\0' * 16, 98: b'\0\x01x\x01v',
                         192: b'\x06\xc0\0\2\1\x18', 258: b'\x03'}[typ]
                ie.from_bytes(self.ie(typ, valid))
                self.assertIsInstance(ie[3], cls)
                self.assertEqual(ie.to_bytes(), self.ie(typ, valid))
