# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import inspect
import logging
import struct
import unittest

import six
from nose.tools import eq_
from nose.tools import ok_

from ryu.lib.packet import pppoe

LOG = logging.getLogger(__name__)


class Test_pppoe_connection(unittest.TestCase):

    ver = 1
    ptype = 1
    code = pppoe.PPPOE_ACTIVE_DISCOVERY_INITIATION
    sid = 0
    total_length = 137
    vslength = 60

    tag_list = [
        pppoe.tag(pppoe.PPPOE_AC_COOKIE, b'test-cookie', 11),
        pppoe.tag(pppoe.PPPOE_AC_NAME, b'test-name', 9),
        pppoe.tag(pppoe.PPPOE_HOST_UNIQ, b'test', 4),
        pppoe.tag(pppoe.PPPOE_SERVICE_NAME, b'service-name', 12),
        pppoe.tag(pppoe.PPPOE_RELAY_SESSION_ID, b'\x01\x02\x03\x04', 4),
        pppoe.tag(pppoe.PPPOE_SERVICE_NAME_ERROR, b'Invalid service name', 20),
        pppoe.tag(pppoe.PPPOE_AC_SYSTEM_ERROR, b'Invalid ac name', 15),
        pppoe.tag(pppoe.PPPOE_GENERIC_ERROR, b'User ended session', 18),
        pppoe.tag(pppoe.PPPOE_VENDOR_SPECIFIC, b'\x00\x00\x0d\xe0', 4),
        pppoe.tag(pppoe.PPPOE_END_OF_LIST, '', 0)
    ]

    vstag_list = [
        pppoe.tag(pppoe.PPPOE_VENDOR_SPECIFIC, [
            3561,
            pppoe.vendor_specific_tag(0x01,
                                      'Access-Node-Identifier eth 3/12',
                                      31),
            pppoe.vendor_specific_tag(0x02,
                                      'Network1234567890',
                                      17)],
                  56)]

    tags = pppoe.tags(tag_list=tag_list, tags_len=137)
    vstags = pppoe.tags(tag_list=vstag_list, tags_len=60)

    pppo = pppoe.pppoe(ver=ver, ptype=ptype, code=code, sid=sid,
                       total_length=total_length, tags=tags)
    vspppo = pppoe.pppoe(ver=ver, ptype=ptype, code=code, sid=sid,
                         total_length=vslength, tags=vstags)

    buf = (
        b"\x11\x09\x00\x00\x00\x89\x01\x04\x00\x0b\x74\x65\x73\x74\x2d\x63"
        b"\x6f\x6f\x6b\x69\x65\x01\x02\x00\x09\x74\x65\x73\x74\x2d\x6e\x61"
        b"\x6d\x65\x01\x03\x00\x04\x74\x65\x73\x74\x01\x01\x00\x0c\x73\x65"
        b"\x72\x76\x69\x63\x65\x2d\x6e\x61\x6d\x65\x01\x10\x00\x04\x01\x02"
        b"\x03\x04\x02\x01\x00\x14\x49\x6e\x76\x61\x6c\x69\x64\x20\x73\x65"
        b"\x72\x76\x69\x63\x65\x20\x6e\x61\x6d\x65\x02\x02\x00\x0f\x49\x6e"
        b"\x76\x61\x6c\x69\x64\x20\x61\x63\x20\x6e\x61\x6d\x65\x02\x03\x00"
        b"\x12\x55\x73\x65\x72\x20\x65\x6e\x64\x65\x64\x20\x73\x65\x73\x73"
        b"\x69\x6f\x6e\x01\x05\x00\x04\x00\x00\x0d\xe0\x00\x00\x00\x00")

    vsbuf = (
        b"\x11\x09\x00\x00\x00\x3c\x01\x05\x00\x38\x00\x00\x0d\xe9\x01\x1f"
        b"\x41\x63\x63\x65\x73\x73\x2d\x4e\x6f\x64\x65\x2d\x49\x64\x65\x6e"
        b"\x74\x69\x66\x69\x65\x72\x20\x65\x74\x68\x20\x33\x2f\x31\x32\x02"
        b"\x11\x4e\x65\x74\x77\x6f\x72\x6b\x31\x32\x33\x34\x35\x36\x37\x38"
        b"\x39\x30")

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.ver, self.pppo.ver)
        eq_(self.ptype, self.pppo.ptype)
        eq_(self.code, self.pppo.code)
        eq_(self.sid, self.pppo.sid)
        eq_(self.total_length, self.pppo.total_length)
        eq_(str(self.tags), str(self.pppo.tags))

    def test_parser(self):
        res, rest = pppoe.pppoe.parser(self.buf)

        eq_(self.ver, res.ver)
        eq_(self.ptype, res.ptype)
        eq_(self.code, res.code)
        eq_(self.sid, res.sid)
        eq_(self.total_length, res.total_length)
        eq_(str(self.tags), str(res.tags))
        eq_(b'', rest)

    def test_vsparser(self):
        res, rest = pppoe.pppoe.parser(self.vsbuf)

        eq_(self.ver, res.ver)
        eq_(self.ptype, res.ptype)
        eq_(self.code, res.code)
        eq_(self.sid, res.sid)
        eq_(self.vslength, res.total_length)
        eq_(str(self.vstags), str(res.tags))
        eq_(b'', rest)

    def test_parser_corrupted(self):
        corrupt_buf = self.buf[:-2]
        pkt, rest = pppoe.pppoe.parser(corrupt_buf)

        ok_(isinstance(pkt, pppoe.pppoe))
        ok_(isinstance(pkt.tags, pppoe.tags))
        for tag in pkt.tags.tag_list[:-1]:
            ok_(isinstance(tag, pppoe.tag))
        ok_(isinstance(pkt.tags.tag_list[-1], six.binary_type))

        buf = pkt.serialize()
        eq_(str(buf), str(corrupt_buf))
        eq_(b'', rest)

    def test_serialize(self):
        buf = self.pppo.serialize()

        res = struct.unpack_from(pppoe.pppoe._PPPOE_PACK_STR,
                                 six.binary_type(buf))

        eq_(self.ptype, res[0] & 0xf)
        eq_(self.ver, res[0] >> 4)
        eq_(self.code, res[1])
        eq_(self.sid, res[2])
        eq_(self.total_length, res[3])
        tags = pppoe.tags.parser(
            buf[struct.calcsize(pppoe.pppoe._PPPOE_PACK_STR):])
        eq_(str(self.tags), str(tags))

    def test_vsserialize(self):
        vsbuf = self.vspppo.serialize()

        res = struct.unpack_from(pppoe.pppoe._PPPOE_PACK_STR,
                                 six.binary_type(vsbuf))

        eq_(self.ptype, res[0] & 0xf)
        eq_(self.ver, res[0] >> 4)
        eq_(self.code, res[1])
        eq_(self.sid, res[2])
        eq_(self.vslength, res[3])
        tags = pppoe.tags.parser(
            vsbuf[struct.calcsize(pppoe.pppoe._PPPOE_PACK_STR):])
        eq_(str(self.vstags), str(tags))

    def test_to_string(self):
        tag_values = ['tg', 'length', 'value']
        tag_str_list = []
        for tag in self.tag_list:
            _tag_str = ','.join(['%s=%s' % (k, repr(getattr(tag, k)))
                                 for k, v in inspect.getmembers(tag)
                                 if k in tag_values])
            tag_str = '%s(%s)' % (pppoe.tag.__name__, _tag_str)
            tag_str_list.append(tag_str)
        tagged_str = '[%s]' % ', '.join(tag_str_list)

        tags_vals = {'tag_list': tagged_str,
                     'tags_len': repr(self.tags.tags_len)}
        _tags_str = ','.join(['%s=%s' % (k, tags_vals[k])
                              for k, v in inspect.getmembers(self.tags)
                              if k in tags_vals])
        tags_str = '%s(%s)' % (pppoe.tags.__name__, _tags_str)

        pppoe_values = {'ver': repr(self.ver),
                        'ptype': repr(self.ptype),
                        'code': repr(self.code),
                        'sid': repr(self.sid),
                        'total_length': repr(self.total_length),
                        'tags': tags_str}
        _pppo_str = ','.join(['%s=%s' % (k, pppoe_values[k])
                              for k, v in inspect.getmembers(self.pppo)
                              if k in pppoe_values])
        pppo_str = '%s(%s)' % (pppoe.pppoe.__name__, _pppo_str)

        eq_(str(self.pppo), pppo_str)
        eq_(repr(self.pppo), pppo_str)

    def test_json(self):
        jsondict = self.pppo.to_jsondict()
        pppo = pppoe.pppoe.from_jsondict(jsondict['pppoe'])
        eq_(str(self.pppo), str(pppo))
