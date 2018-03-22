# this module is provided by the pyscard package
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.System import readers

from binascii import hexlify
import math


errorchecker = ISO7816_4ErrorChecker()


def construct_APDU(cla, ins, p1, p2, data, le):
    """ Constructs an APDU according to ISO 7816.
    note that CLA is defined for 0x0X,
                     reserved for 0x10 to 0x7F
    """
    lc = len(data)
    if lc == 0:
        lc_bytes = []
    elif lc < 2**8:
        lc_bytes = [lc]
    else:
        raise Exception("Nc cannot exceed 255 bytes.")
    if le == 0:
        le_bytes = []
    elif le <= 2 ** 8:
        le_bytes = [le % 2 ** 8]  # mod such that le = 256 implies 0x00
    else:
        raise Exception("Ne cannot exceed 256 bytes.")
    if type(data) is bytes:
        data = list(data)
    return [cla, ins, p1, p2] + lc_bytes + data + le_bytes


def construct_256bytes_APDU(cla, ins, x, le=0):
    outbytes = x.to_bytes(math.ceil(x.bit_length() / 8), byteorder='big')
    return construct_APDU(cla, ins, outbytes[0], 0, outbytes[1:], le)


def select_AID_APDU(aid):
    return construct_APDU(0x00, 0xA4, 0x04, 0x00, aid, 0)


def output_errors(data, sw1, sw2):
    if (sw1 << 8) + sw2 != 0x9000:
        print(hex((sw1 << 8) + sw2))
    errorchecker(data, sw1, sw2)


def connect(aid):
    print("Connecting to reader..")

    reader = readers()[0]
    connection = reader.createConnection()
    connection.connect()

    print("Selecting applet..")

    data, sw1, sw2 = connection.transmit(select_AID_APDU(aid))
    output_errors(data, sw1, sw2)

    return connection
