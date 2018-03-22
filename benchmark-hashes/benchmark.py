import time
import apdus

CLA = 0x80
PID = [0x58, 0x4D, 0x53, 0x53, 0x43, 0x41, 0x52, 0x44]
AID = PID + [0x48, 0x41, 0x53, 0x48]
connection = apdus.connect(AID)

print("Selected applet; running benchmark")

t0 = time.time()

data, sw1, sw2 = connection.transmit(
    apdus.construct_APDU(CLA, 0, 0, 0, [], 0)
)
apdus.output_errors(data, sw1, sw2)

t1 = time.time()

print("That took {:.4f} seconds".format(t1 - t0))
