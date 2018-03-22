## Java Card XMSS

This repository contains an implementation of XMSS (as described in the [Internet Draft _"XMSS: Extended Hash-Based Signatures"_](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/)) for the Java Card platform. Check back soon for a reference to the paper describing this implementation and the motivating research.

Note that this is a proof-of-concept implementation. Do **NOT** simply use this in production environments without thorough review. This implementation is still under construction, and may be subject to change.

### Installation

This project depends on the [xmss-reference](https://github.com/joostrijneveld/xmss-reference) and [oracle_javacard_sdks](https://github.com/martinpaljak/oracle_javacard_sdks) repositories. Before all else, be sure to call `git submodule update --init`.

To use the C code on the host side, we rely on the PCSC library. PCSC is bundled with Windows by default, and is available through the [PCSClite project](https://pcsclite.apdu.fr/) on Linux. A fork comes pre-installed on macOS as well.

To use the Python scripts on the host-side, we rely on [pyserial](https://github.com/pyserial/pyserial).

To build and install the applets on a Java Card, run `ant install-222` or `ant install-304` (depending on the version of your Java Card) in the respective subdirectories. This requires [ant-javacard.jar](https://github.com/martinpaljak/ant-javacard/releases/download/v1.8/ant-javacard.jar) in the same directory.

### Tests and benchmarks

To test the XMSS applet, simply `make`  and `./test` in the `xmss/host` directory.

To benchmark a specific hash function's runtime, modify the `benchmark-hashes/smartcard/Hash.java` file accordingly, and run the `benchmark.py` Python script.

### Documentation

See [xmss/APDUs.md](xmss/APDUs.md) for documentation of the APDUs as used in this implementation.
