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

"""
PPPoE packet parser/serializer.
"""
# RFC 2516
# PPPoE packet format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  VER  | TYPE  |      CODE     |          SESSION_ID           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |            LENGTH             |           payload             ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# The PPPoE payload contains zero or more TAGs A TAG is a TLV (type-
# length-value) construct and is defined as follows:
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          TAG_TYPE             |        TAG_LENGTH             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          TAG_VALUE ...                                        ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

import struct
from ryu.lib import stringify
from . import packet_base

# PPPoE message type code
PPPOE_ACTIVE_DISCOVERY_INITIATION = 0x09
PPPOE_ACTIVE_DISCOVERY_OFFER = 0x07
PPPOE_ACTIVE_DISCOVERY_REQUEST = 0x19
PPPOE_ACTIVE_DISCOVERY_SESSION = 0x65
PPPOE_ACTIVE_DISCOVERY_TERMINATE = 0xa7
PPPOE_SESSION = 0x00

# PPPoE Tag List
PPPOE_END_OF_LIST = 0x0000
PPPOE_SERVICE_NAME = 0x0101
PPPOE_AC_NAME = 0x0102
PPPOE_HOST_UNIQ = 0x0103
PPPOE_AC_COOKIE = 0x0104
PPPOE_VENDOR_SPECIFIC = 0x0105
PPPOE_RELAY_SESSION_ID = 0x0110
PPPOE_SERVICE_NAME_ERROR = 0x0201
PPPOE_AC_SYSTEM_ERROR = 0x0202
PPPOE_GENERIC_ERROR = 0x0203

# PPPoE Vendor Specific Sub Option codes
PPPOE_CIRCUIT_ID = 0x01
PPPOE_REMOTE_ID = 0x02


class pppoe(packet_base.PacketBase):
    """PPPoE (RFC 2516) header encoder/decoder class.

    The serialized packet would look like the ones described in
    the following sections.

    * RFC 2516 A method for Transmitting PPP Over Ethernet (PPPoE)

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order

    .. tabularcolumns:: |l|L|

    =============== ====================
    Attribute       Description
    =============== ====================
    ver             Version of the PPPoE specification
    ptype           PPPoE type field
    code            PPPoE code
    sid             Session ID is used in Discovery packets. The value is fixed
                    for a given PPP session and is used to define a PPP session
                    along with the eth src and dst address
    total_length    Total length
    tags            List of `PPPoETags` \
                    None if no tags
    =============== ====================
    """

    _PPPOE_PACK_STR = "!BBHH"
    _MIN_LEN = struct.calcsize(_PPPOE_PACK_STR)
    _class_prefixes = ['tags']

    def __init__(self, ver=0x1, ptype=0x1, code=0, sid=0x0000,
                 total_length=0, tags=None):
        super(pppoe, self).__init__()
        self.ver = ver
        self.ptype = ptype
        self.code = code
        self.sid = sid
        self.total_length = total_length
        self.tags = tags

    @classmethod
    def parser(cls, buf):
        (ver, code, sid,
         total_length) = struct.unpack_from(cls._PPPOE_PACK_STR, buf)
        ptype = ver & 0xf
        ver = ver >> 4
        length = cls._MIN_LEN
        parse_tags = None
        if len(buf) > length:
            parse_tags = tags.parser(buf[length:])
            length += parse_tags.tags_len

        return (cls(ver, ptype, code, sid, total_length, parse_tags),
                buf[length:])

    def serialize(self, _payload=None, _prev=None):
        tag_buf = bytearray()
        if self.tags is not None:
            tag_buf = self.tags.serialize()
        version = self.ver << 4 | self.ptype
        return struct.pack(self._PPPOE_PACK_STR, version, self.code, self.sid,
                           self.total_length) + tag_buf


class tags(stringify.StringifyMixin):
    """PPPoE (RFC 2516) tags encode/decoder class.

    This is used with ryu.lib.packet.pppoe.pppoe.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ====================
    Attribute       Description
    =============== ====================
    tag_list        List of tags present
    tags_len        Tag's byte length
    =============== ====================
    """
    _TAG_LEN_BYTE = 4
    _class_prefixes = ['tag']

    def __init__(self, tag_list=None, tags_len=0):
        super(tags, self).__init__()
        self.tag_list = tag_list or []
        self.tags_len = tags_len

    @classmethod
    def parser(cls, buf):
        tag_parse_list = []
        offset = 0
        while len(buf) > offset:
            tag_buf = buf[offset:]
            try:
                tag_ = tag.parser(tag_buf)
            except struct.error:
                tag_parse_list.append(tag_buf)
                break
            if tag_ is None:
                break
            tag_parse_list.append(tag_)
            offset += tag_.length + cls._TAG_LEN_BYTE
        return cls(tag_parse_list, len(buf))

    def serialize(self):
        seri_tag = ""
        for tag_ in self.tag_list:
            if isinstance(tag_, tag):
                seri_tag += tag_.serialize()
            else:
                seri_tag += tag_
        self.tags_len = len(seri_tag)
        return seri_tag


class tag(stringify.StringifyMixin):
    """PPPoE (RFC 2516) tags encoder/decoder class.

    This is used with ryu.lib.packet.pppoe.pppoe.tags

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ====================
    Attribute       Description
    =============== ====================
    tag_type        Tag type
    value           Tag's value. \
                    (set the value that has been converted to hexadecimal.)
    length          Tag's value length. \
                    (calculated automatically from the length of the value.)
    =============== ====================
    """
    _UNPACK_STR = "!HH"
    _MIN_LEN = struct.calcsize(_UNPACK_STR)
    _VENDOR_ID_UNPACK_STR = '!I'
    _BBF_IANA_ENTRY = 0x00000DE9
    _TAG_LEN_BYTE = 2

    def __init__(self, tag_type, value, length=0):
        super(tag, self).__init__()
        self.tag_type = tag_type
        self.value = value
        self.length = length

    @classmethod
    def parser(cls, buf):
        (tag_type, length) = struct.unpack_from(cls._UNPACK_STR, buf)
        buf = buf[cls._MIN_LEN:]

        if tag_type != PPPOE_VENDOR_SPECIFIC:
            value_unpack_str = '%ds' % length
            value = struct.unpack_from(value_unpack_str, buf)[0]
            return cls(tag_type, value, length)

        tag_value = struct.unpack_from(cls._VENDOR_ID_UNPACK_STR, buf)[0]
        if tag_value != cls._BBF_IANA_ENTRY:
            value_unpack_str = '%ds' % length
            value = struct.unpack_from(value_unpack_str, buf)[0]
            return cls(tag_type, value, length)

        offset = struct.calcsize(cls._VENDOR_ID_UNPACK_STR)
        value = [tag_value]
        while length > offset:
            sub_tag_buf = buf[offset:]
            try:
                sub_tag = VendorTag.parser(sub_tag_buf)
            except struct.error:
                value.append(sub_tag_buf)
                break
            if sub_tag is None:
                break
            value.append(sub_tag)
            offset += sub_tag.length + cls._TAG_LEN_BYTE
        return cls(tag_type, value, length)

    def serialize(self):
        if self.value is None:
            self.value = ''
        value = ""
        vendor_id = None
        for val in self.value:
            if isinstance(val, VendorTag):
                value += val.serialize()
            else:
                if val == 3561:
                    vendor_id = val
                else:
                    value += str(val)
        self.length = len(value)
        if vendor_id:
            tags_pack_str = '!HHI%ds' % self.length
            self.length += struct.calcsize('!I')
            return struct.pack(tags_pack_str, self.tag_type, self.length,
                               vendor_id, value)

        tags_pack_str = '!HH%ds' % self.length
        return struct.pack(tags_pack_str, self.tag_type, self.length, value)


class VendorTag(stringify.StringifyMixin):
    """PPPoE access loop identification tag (Broadband Forum TR-101)

    This is used with ryu.lib.packet.pppoe.pppoe.tags.tag.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the corresponding args in this order.

    .. tabularcolumns:: |l|L|

    =============== ====================
    Attribute       Description
    =============== ====================
    code            Sub option code / option code. \
                    1 =  Agent Circuit ID, 2 = Agent Remote ID
    value           Sub option's value. \
                    (Set the value that has been converted to hexadecimal.)
    length          Sub option's length. \
                    (calculated automatically from the length of value.)
    =============== ====================
    """
    _UNPACK_STR = "!BB"
    _MIN_LEN = struct.calcsize(_UNPACK_STR)

    def __init__(self, code, value, length=0):
        super(VendorTag, self).__init__()
        self.code = code
        self.value = value
        self.length = length

    @classmethod
    def parser(cls, buf):
        (code, length) = struct.unpack_from(cls._UNPACK_STR, buf)
        buf = buf[cls._MIN_LEN:]
        value_unpack_str = '%ds' % length
        value = struct.unpack_from(value_unpack_str, buf)[0]
        return cls(code, value, length)

    def serialize(self):
        self.length = len(self.value)
        tag_pack_str = '!BB%ds' % self.length
        return struct.pack(tag_pack_str, self.code, self.length, self.value)
