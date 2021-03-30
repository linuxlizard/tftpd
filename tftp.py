#!/usr/bin/python

import struct

UDP_PORT = 69

RRQ = 1  # Read request
WRQ = 2  # Write request
DATA = 3
ACK = 4
ERROR = 5

opcode_strings = ("(unknown)", "RRQ", "WRQ", "DATA", "ACK", "ERROR")
opcode_names = (
    "(unknown)",
    "Read Request",
    "Write Request",
    "Data",
    "Acknowledgement",
    "Error",
)

# Error Codes
#   Value	 Meaning
#   0		 Not defined, see error message (if any).
#   1		 File not found.
#   2		 Access violation.
#   3		 Disk full or allocation exceeded.
#   4		 Illegal TFTP operation.
#   5		 Unknown transfer ID.
#   6		 File already exists.
#   7		 No such user.
ERROR_UNDEFINED = 0
ERROR_NO_SUCH_FILE = 1
ERROR_ACCESS_VIOLATION = 2
ERROR_DISK_FULL = 3
ERROR_ILLEGAL_TFTP_OP = 4
ERROR_UNKNOWN_TRANSFER_ID = 5
ERROR_FILE_EXISTS = 6
ERROR_NO_SUCH_USER = 7

# useful for debugging
def hexdump(str):
    for c in str:
        print("%02x" % ord(c), end=" ")
    print()


class packet_error:
    pkt = ""
    errmsg = ""

    def __init__(self, pkt, errmsg):
        self.pkt = pkt
        self.errmsg = errmsg

    def __str__(self):
        return "Packet error : %s" % self.errmsg


class Packet:
    op = 0
    packet = ""  # raw, encoded packet, ready to be sent onto the network

    def __init__(self, buffer=""):
        self.packet = buffer

    def __str__(self):
        str = opcode_strings[self.op]
        return str


class Request(Packet):
    filename = ""
    mode = ""

    def __init__(self, filename="", mode=""):
        Packet.__init__(self)
        self.filename = filename
        self.mode = mode.lower()

    def pack(self):
        if type(self.filename) != type(b''):
            filename = self.filename.encode("utf8")
        else:
            filename = self.filename
        if type(self.mode) != type(b''):
            mode = self.mode.encode("utf8")
        else:
            mode = self.mode
        self.packet = struct.pack(
            ("!H%dsc%dsc" % (len(self.filename), len(self.mode))),
            self.op,
            filename,
            b"\x00",
            mode,
            b"\x00",
        )

    def unpack(self):
        """Parse a WRQ or RRQ, verifying pkt, extracting filename and mode."""
        self.op, pkt = struct.unpack(("!H%ds" % (len(self.packet) - 2)), self.packet)
        fields = pkt.split(b"\x00")
        print(fields)
        # there are two fields, but the split will give us three with the empty
        # string after the final NULL
        # 		if len(fields) != 3 or len(fields[2]) != 0 :
        # 			raise packet_error( pkt, ("Bad %s (%s); couldn't find the filename and mode fields." \
        # 					% (opcode_strings[self.op],opcode_names[self.op]) ) )
        self.filename = fields[0].decode()
        self.mode = fields[1].lower().decode()

    def __str__(self):
        str = Packet.__str__(self)
        str = str + " filename=%s mode=%s" % (self.filename, self.mode)
        return str


class ReadRequest(Request):
    def __init__(self, filename="", mode=""):
        Request.__init__(self, filename, mode)
        self.op = RRQ


class WriteRequest(Request):
    def __init__(self, filename="", mode=""):
        Request.__init__(self, filename, mode)
        self.op = WRQ


class Ack(Packet):
    block_num = 0

    def __init__(self, block_num=0):
        Packet.__init__(self)
        self.op = ACK
        self.block_num = block_num

    def pack(self):
        self.packet = struct.pack("!HH", self.op, self.block_num)

    def unpack(self):
        """Parse an ACK, verifying pkt, extracting block number."""
        if len(self.packet) < 4:
            raise packet_error(
                self.packet, "Packet too small (len=%d)." % len(self.packet)
            )
        self.op, self.block_num, junk = struct.unpack(
            ("!HH%ds" % (len(self.packet) - 4)), self.packet
        )

    def __str__(self):
        str = Packet.__str__(self)
        str = str + " block=%d" % self.block_num
        return str


class Data(Packet):
    block_num = 0
    data = ""

    def __init__(self, data=""):
        Packet.__init__(self)
        self.op = DATA
        self.data = data
        self.block_num = 0

    def pack(self):
        assert len(self.data) <= 512
        if type(self.data) != type(b''):
            data = self.data.encode()
        else:
            data = self.data
        self.packet = struct.pack(
            ("!HH%ds" % len(self.data)), self.op, self.block_num, data
        )

    def unpack(self):
        """Parse a DATA, verifying pkt, extracting data field and block number."""
        if len(self.packet) > 516:
            raise packet_error(
                self.packet, "Packet too large (len=%d)." % len(self.packet)
            )
        self.op, self.block_num, self.data = struct.unpack(
            ("!HH%ds" % (len(self.packet) - 4)), self.packet
        )

    def __str__(self):
        str = Packet.__str__(self)
        str = str + " block=%d datalen=%d" % (self.block_num, len(self.data))
        return str


class Error(Packet):
    error_code = 0
    error_msg = ""

    def __init__(self, error_code=0, error_msg=""):
        Packet.__init__(self)
        self.op = ERROR
        self.error_code = error_code
        self.error_msg = error_msg

    def pack(self):
        if type(self.error_msg) != type(b''):
            error_msg = self.error_msg.encode()
        else:
            error_msg = self.error_msg
        self.packet = struct.pack(
            ("!HH%dsc" % len(self.error_msg)),
            self.op,
            self.error_code,
            error_msg,
            b"\x00",
        )

    def unpack(self):
        self.op, self.error_code, error_msg = struct.unpack(
            ("!HH%ds" % (len(self.packet) - 4)), self.packet
        )
        # take up to the first NULL as the error message
        self.error_msg = error_msg.split(b"\x00")[0]

    def __str__(self):
        str = Packet.__str__(self)
        str = str + ' error_code=%d error_msg="%s"' % (self.error_code, self.error_msg)
        return str


debugging = 0


def parse(buffer):
    """A class factory of sorts.  Take a raw buffer, partially parse it, then
    instantiate and return a new class for that packet."""

    op, pkt = struct.unpack(("!H%ds" % (len(buffer) - 2)), buffer)

    if op == RRQ:
        pkt = ReadRequest()
    elif op == WRQ:
        pkt = WriteRequest()
    elif op == DATA:
        pkt = Data()
    elif op == ACK:
        pkt = Ack()
    elif op == ERROR:
        pkt = Error()
    else:
        raise packet_error(packet, ("Bad opcode %02x in packet" % op))

    pkt.packet = buffer
    pkt.unpack()

    if debugging:
        print(pkt)
    return pkt


def __pack_test(pkt):
    pkt.pack()
    pkt.unpack()
    pkt.pack()
    print(pkt)
    print(parse(pkt.packet))


if __name__ == "__main__":

    rd = ReadRequest()
    __pack_test(rd)
    rd = ReadRequest("/etc/foo/bar", "octet")
    __pack_test(rd)

    wr = WriteRequest()
    __pack_test(wr)
    wr = WriteRequest("/etc/foo/bar", "octet")
    __pack_test(wr)

    ack = Ack()
    __pack_test(ack)
    ack = Ack(99)
    __pack_test(ack)

    data = Data()
    __pack_test(data)
    data = Data("This is a test")
    __pack_test(data)

    err = Error()
    __pack_test(err)
    err = Error(ERROR_FILE_EXISTS, "Foo! Bar! Baz!")
    __pack_test(err)
