import struct

from ipaddress import IPv4Address
from switchyard.lib.userlib import *

class DynamicRoutingMessage(PacketHeaderBase):
    _PACKFMT = "qxqxq"

    def __init__(self, advertised_prefix="0.0.0.0",
                 advertised_mask="0.0.0.0",
                 next_hop="0.0.0.0",
                 **kwargs):
        self._advertised_prefix = IPv4Address(advertised_prefix)
        self._advertised_mask = IPv4Address(advertised_mask)
        self._next_hop = IPv4Address(next_hop)
        PacketHeaderBase.__init__(self, **kwargs)

    def to_bytes(self):
        raw = struct.pack(self._PACKFMT,
                          int(self._advertised_prefix),
                          int(self._advertised_mask),
                          int(self._next_hop))
        return raw

    def from_bytes(self, raw):
        packsize = struct.calcsize(self._PACKFMT)
        if len(raw) < packsize:
            raise ValueError("Not enough bytes to unpack DynamicRoutingMessage")
        xprefix, xmask, xnexthop = struct.unpack(self._PACKFMT, raw[:packsize])
        self._advertised_prefix = IPv4Address(xprefix)
        self._advertised_mask = IPv4Address(xmask)
        self._next_hop = IPv4Address(xnexthop)
        return raw[packsize:]

    @property
    def advertised_prefix(self):
        return self._advertised_prefix

    @property
    def advertised_mask(self):
        return self._advertised_mask

    @property
    def next_hop(self):
        return self._next_hop

    def __str__(self):
        return "{} (advertised_prefix: {}, advertised_mask: {}, next_hop: {})".\
            format(self.__class__.__name__, self.advertised_prefix,
self.advertised_mask, self.next_hop)