package applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

public class XMSS {
    /* We're typically interested in the lowest byte of an address, or one
       higher byte (in which case we subtract one). */
    public static final short ADDR_LAYER_LSBYTE = 3;
    public static final short ADDR_TREE_HIGH_LSBYTE = 7;
    public static final short ADDR_TREE_LOW_LSBYTE = 11;
    public static final short ADDR_TYPE_LSBYTE = 15;
    public static final short ADDR_OTS_LSBYTE = 19;
    public static final short ADDR_CHAIN_LSBYTE = 23;
    public static final short ADDR_HASH_LSBYTE = 27;
    public static final short ADDR_TREE_HEIGHT_LSBYTE = 23;
    public static final short ADDR_TREE_INDEX_LSBYTE = 27;
    public static final short ADDR_KEY_MASK_LSBYTE = 31;

    public static final byte DOMAINSEP_F = (byte)0;
    public static final byte DOMAINSEP_H = (byte)1;
    public static final byte DOMAINSEP_HASH = (byte)2;
    public static final byte DOMAINSEP_PRF = (byte)3;

    public static final byte ADDRTYPE_OTS = (byte)0;
    public static final byte ADDRTYPE_LTREE = (byte)1;
    public static final byte ADDRTYPE_HASHTREE = (byte)2;

    public static final short WOTS_W = 16;  /* Only supports WOTS_W == 16 */
    public static final short WOTS_LOG_W = 4;
    public static final short WOTS_LEN1 = 64;
    public static final short WOTS_LEN2 = 3;
    public static final short WOTS_LEN = 67;
    /* This implementation assumes H/D <= 15, to simplify the arithmetic */
    public static final short D = 5;  /* Number of subtrees */
    /* This implementation assumes H <= 30; indices are two signed shorts */
    public static final short H = 20;  /* Height of the full tree */
    /* This implementation assumes N = 32 in various (unexpected?) ways */
    public static final short N = 32;  /* Size of a hash output */

    private final MessageDigest md;
    private final short[] tmpShorts;
    /* This array contains all nodes of the trees that we're precomputing
       for authentication path generation. */
    private final byte[] nodes;
    /* If initialized externally, track how many bytes are received */
    private short nodeBytesReceived = 0;
    private short WOTSBytesReceived = 0;
    /* This is a potential problem: depending on the threat model, the secret
       key should not be stored as a bytearray, but in a way that guarantees
       side-channel countermeasures. There is no generic solution available. */
    private final byte[] secretKey;  /* SKSEED + PRFKEY */
    private final byte[] publicKey;  /* ROOT + PUBSEED */

    /* This array stores all WOTS signatures currently in use.
       Newly created signatures immediately overwrite older signatures */
    private final byte[] WOTSSignatures;

    /* The index can be 2^20 for tree height 20, so we split into two shorts,
       i.e. the index is (indexHigh << 15 + indexLow)
       (it's awkward like this because short is a signed integer) */
    private short indexHigh;
    private short indexLow;

    /* During signing, we keep track of an index throughout the tree. */
    private short signingIdxHigh;
    private short signingIdxLow;

    /* Between APDUs, must store the current root node that we are signing.
       This also initially holds the message hash signed by the bottom WOTS. */
    private final byte[] signingRoot;
    /* It is important that we keep accurate track of our position in the
       signing state machine, to avoid being tricked into signing different
       data with the same one=time-signature keypair. */
    /* State 0: generate R
       State-1 == 0 mod 16: 8 WOTS chains
       State-1 == 1 mod 16: 8 WOTS chains
       State-1 == 2 mod 16: 8 WOTS chains
       [..]
       State-1 == 7 mod 16: 8 WOTS chains
       State-1 == 8 mod 16: 3 WOTS chains
       State-1 == 9 mod 16: H/D treehash nodes
       State-1 == 10 mod 16: preparing next nodes (only once per signature)
       State-1 == 11-15 are unassigned */
    /* This implies that '(State-1) / 16' gives the subtree layer */
    private short signingState;

    public XMSS(MessageDigest md) {
        this.md = md;
        /* Dominated by the WOTS chain lengths (and not treehash levels). */
        tmpShorts = JCSystem.makeTransientShortArray((short)67, JCSystem.CLEAR_ON_DESELECT);
        /* 2*D-1 layers of leaf nodes; current and next tree for each layer,
           and only 'current' for the topmost layer. */
        nodes = new byte[(short)(N * (2*D - 1) * (1 << (H / D)))];
        WOTSSignatures = new byte[(short)(WOTS_LEN * N * (D - 1))];
        secretKey = new byte[64];
        publicKey = new byte[64];

        signingRoot = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        /* Invalidate the signing state; initialized upon key generation */
        signingState = -1;
    }

    /* Assumes that tmp starts with 31 zeroes, has a total of 64 bytes.
       Destroys the input buffer's contents; input and output can overlap. */
    private void hashf(byte[] out, short o_out,
                       byte[] ots_addr, short o_addr,
                       byte[] in, short o_in,
                       byte[] tmp, short o_tmp) {
        short i;

        tmp[(short)(o_tmp + N-1)] = DOMAINSEP_PRF;

        /* Compute the mask */
        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(publicKey, N, N);  /* PUBSEED */
        ots_addr[(short)(o_addr + ADDR_KEY_MASK_LSBYTE)] = 1;
        md.doFinal(ots_addr, o_addr, (short)32, tmp, (short)(o_tmp + N));

        /* Mask the input */
        for (i = 0; i < N; i++) {
            in[(short)(o_in + i)] ^= tmp[(short)(o_tmp + N + i)];
        }

        /* Compute the key */
        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(publicKey, N, N);  /* PUBSEED */
        ots_addr[(short)(o_addr + ADDR_KEY_MASK_LSBYTE)] = 0;
        md.doFinal(ots_addr, o_addr, (short)32, tmp, (short)(o_tmp + N));

        /* Combine to compute the output */
        tmp[(short)(o_tmp + N-1)] = DOMAINSEP_F;
        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(tmp, (short)(o_tmp + N), N);  /* Key */
        md.doFinal(in, o_in, N, out, o_out);  /* Masked input */
    }

    /* Assumes tmp starts with 31 zeroes and has 128 bytes available in total.
       Preserves the input, which is useful in stored hash trees.*/
    private void hashh(byte[] out, short o_out,
                       byte[] addr, short o_addr,
                       byte[] in1, short o_in1,
                       byte[] in2, short o_in2,
                       byte[] tmp, short o_tmp) {
        short i;

        tmp[(short)(o_tmp + N-1)] = DOMAINSEP_PRF;

        /* Compute the mask */
        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(publicKey, N, N);  /* PUBSEED */
        addr[(short)(o_addr + ADDR_KEY_MASK_LSBYTE)] = 1;
        md.doFinal(addr, o_addr, (short)32, tmp, (short)(o_tmp + 2*N));

        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(publicKey, N, N);  /* PUBSEED */
        addr[(short)(o_addr + ADDR_KEY_MASK_LSBYTE)] = 2;
        md.doFinal(addr, o_addr, (short)32, tmp, (short)(o_tmp + 3*N));

        /* Mask the input; preserve the input by masking into tmp */
        for (i = 0; i < 32; i++) {
            tmp[(short)(o_tmp + 2*N + i)] ^= in1[(short)(o_in1 + i)];
        }
        for (i = 0; i < 32; i++) {
            tmp[(short)(o_tmp + 3*N + i)] ^= in2[(short)(o_in2 + i)];
        }

        /* Compute the key */
        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(publicKey, N, N);  /* PUBSEED */
        addr[(short)(o_addr + ADDR_KEY_MASK_LSBYTE)] = 0;
        md.doFinal(addr, o_addr, (short)32, tmp, (short)(o_tmp + N));

        /* Combine to compute the output */
        tmp[(short)(o_tmp + N-1)] = DOMAINSEP_H;
        md.update(tmp, o_tmp, N);  /* Domain separator */
        md.update(tmp, (short)(o_tmp + N), N);  /* Key */
        md.doFinal(tmp, (short)(o_tmp + 2*N), (short)(2*N),  /* Masked input */
                   out, o_out);
    }

    /* Iterates F calls to compute the WOTS chaining output.
       Destroys the input, allows overlapping input and output.
       Requirements on tmp inherit from hashf. */
    public void WOTSChain(byte[] out, short o_out,
                          byte[] addr, short o_addr,
                          byte[] in, short o_in,
                          byte[] tmp, short o_tmp,
                          short chainlen) {
        for (short i = 0; i < chainlen; i++) {
            addr[(short)(o_addr + ADDR_HASH_LSBYTE)] = (byte)(0xFF & i);
            hashf(in, o_in, addr, o_addr, in, o_in, tmp, o_tmp);
        }
        Util.arrayCopyNonAtomic(in, o_in, out, o_out, N);
    }

    /* Converts msg to baseW and writes results to lengths array, for the
       purpose of creating WOTS chains. */
    private void baseW(short[] lengths, short offset,
                       byte[] msg, short o_msg, short msgLength) {
        short in = 0;
        short out = 0;
        byte total = 0;
        short bits = 0;
        short consumed;

        for (consumed = 0; consumed < msgLength; consumed++) {
            if (bits == 0) {
                total = msg[(short)(o_msg + in)];
                in++;
                bits += 8;
            }
            bits -= WOTS_LOG_W;
            lengths[(short)(out + offset)] = (short)((total >>> bits) & (WOTS_W - 1));
            out++;
        }
    }

    /* Computes the WOTS+ checksum over a message (in base WOTS_W).
       Requires 2 bytes of temporary data in tmp. */
    private void WOTSChecksum(short[] checksumLengths, short[] msgLengths,
                              byte[] tmp, short o_tmp) {
        short csum = 0; /* At most WOTS_LEN1 * WOTS_W */
        short i;

        /* Compute checksum */
        for (i = 0; i < WOTS_LEN1; i++) {
            csum += (short)(WOTS_W - 1 - msgLengths[i]);
        }

        /* Ensure expected empty (zero) bits are the least significant bits. */
        csum <<= (short)((8 - ((short)(WOTS_LEN2 * WOTS_LOG_W) % 8)));
        /* For W = 16 N = 32, the checksum fits in 10 < 15 bits */
        Util.setShort(tmp, o_tmp, csum);

        /* Convert checksum to base W */
        baseW(checksumLengths, WOTS_LEN1, tmp, o_tmp, WOTS_LEN2);
    }

    /* Takes a message and derives the corresponding chain lengths.
       Required space in tmp is inherited from WOTSChecksum. */
    private void chainLengths(short[] lengths, byte[] msg,
                              byte[] tmp, short o_tmp) {
        baseW(lengths, (short)0, msg, (short)0, WOTS_LEN1);
        WOTSChecksum(lengths, lengths, tmp, o_tmp);
    }

    /* Computes an OTS seed; writes [31x 0, DOMAINSEP] to tmp as side-effect */
    private void WOTSGetSeed(byte[] seed, short o_seed,
                             byte[] addr, short o_addr,
                             byte[] tmp, short o_tmp) {
        Util.arrayFillNonAtomic(tmp, o_tmp, (short)31, (byte)0);
        tmp[(short)(o_tmp + 31)] = DOMAINSEP_PRF;
        md.update(tmp, o_tmp, N);
        md.update(secretKey, (short)0, (short)32);

        /* Zero out CHAIN, HASH and KEY_AND_MASK fields */
        Util.arrayFillNonAtomic(addr, (short)(o_addr + ADDR_CHAIN_LSBYTE-3),
                                (short)12, (byte)0);

        md.doFinal(addr, o_addr, (short)32, seed, o_seed);
    }

    /* Writes the seed to `out`, expects domainSep to be [31x ZERO, 1x ??] */
    private void WOTSComputeChainseed(byte[] out, short o_out,
                                      byte[] domainSep, short o_domainSep,
                                      byte[] WOTSSeed, short o_WOTSSeed,
                                      byte chain) {
        domainSep[(short)(o_domainSep + 31)] = DOMAINSEP_PRF;
        md.update(domainSep, o_domainSep, (short)32);
        md.update(WOTSSeed, o_WOTSSeed, (short)32);
        domainSep[(short)(o_domainSep + 31)] = chain;
        md.doFinal(domainSep, o_domainSep, (short)32, out, o_out);
    }

    /* root will contain the 32-byte output, addr is expected to be 32 bytes,
       tmp is needed for 13x32 intermediate bytes.
       This very strongly assumes that WOTS_W = 16. */
    private void WOTSLeafGen(byte[] root, short o_root,
                             byte[] addr, short o_addr,
                             byte[] tmp, short o_tmp) {
        short i;
        short offset = 0;
        byte leaf = 0;

        md.reset();
        WOTSGetSeed(tmp, o_tmp, addr, o_addr, tmp, (short)(o_tmp + 64));

        /* tmp now contains [wots_seed] [??] [31x 0, DOMAINSEP_PRF] */

        /* Use treehash to compute the regular part of the ltree */
        for (leaf = 0; leaf < 64; leaf++) {
            WOTSComputeChainseed(tmp, (short)(o_tmp + 32),
                                 tmp, (short)(o_tmp + 64),
                                 tmp, o_tmp,
                                 leaf);

            /* tmp now contains [wots_seed] [chainseed] [31x 0, DOMAINSEP] [3x32 reserved] [6x32 reserved] */
            /* Reserved space is for hashh and the nodes on the treehash stack */
            addr[ADDR_TYPE_LSBYTE] = ADDRTYPE_OTS;
            addr[ADDR_CHAIN_LSBYTE] = leaf;

            /* Compute the next leaf of the ltree, push to the stack */
            WOTSChain(tmp, (short)(o_tmp + 6*32 + offset*32),
                      addr, o_addr,
                      tmp, (short)(o_tmp + 32),
                      tmp, (short)(o_tmp + 64), (short)(WOTS_W - 1));
            tmpShorts[offset] = 0;
            offset++;

            /* While the two topmost nodes on the stack are of the same height,
               hash them together. */
            while (offset >= 2 && tmpShorts[(short)(offset - 1)] ==
                                  tmpShorts[(short)(offset - 2)]) {
                addr[ADDR_TYPE_LSBYTE] = ADDRTYPE_LTREE;
                addr[ADDR_TREE_INDEX_LSBYTE] = (byte)(leaf >>> (tmpShorts[(short)(offset - 1)] + 1));
                addr[ADDR_TREE_HEIGHT_LSBYTE] = (byte)tmpShorts[(short)(offset - 1)];
                /* Overwrite one of the inputs, pop the other off the stack */
                hashh(tmp, (short)(o_tmp + 6*32 + (offset - 2)*32),
                      addr, o_addr,
                      tmp, (short)(o_tmp + 6*32 + (offset - 2)*32),
                      tmp, (short)(o_tmp + 6*32 + (offset - 1)*32),
                      tmp, (short)(o_tmp + 64));
                offset--;
                /* Note that the top-most node is now one layer higher. */
                tmpShorts[(short)(offset - 1)]++;
            }
        }

        /* The remaining three we do manually, to simplify ltree treehash;
           the alternative would be to make it generic w.r.t. pulling up nodes,
           but since we fix WOTS_W = 16, it is clear which nodes are lifted. */
        /* tmp[o_tmp + 6*32 + 0*32] contains (sub-)root of first 64 leafs. */

        /* Compute the three remaining leafs */
        addr[ADDR_TYPE_LSBYTE] = ADDRTYPE_OTS;
        for (leaf = 64; leaf < 67; leaf++) {
            WOTSComputeChainseed(tmp, (short)(o_tmp + 32),
                                 tmp, (short)(o_tmp + 64),
                                 tmp, o_tmp,
                                 leaf);
            addr[ADDR_CHAIN_LSBYTE] = leaf;
            WOTSChain(tmp, (short)(o_tmp + 6*32 + (leaf - 64 + 1)*32),
                      addr, o_addr,
                      tmp, (short)(o_tmp + 32),
                      tmp, (short)(o_tmp + 64), (short)(WOTS_W - 1));
        }

        addr[ADDR_TYPE_LSBYTE] = ADDRTYPE_LTREE;

        /* Combine the 65th and 66th leaf */
        addr[ADDR_TREE_INDEX_LSBYTE] = 64 >>> 1;
        addr[ADDR_TREE_HEIGHT_LSBYTE] = 0;
        hashh(tmp, (short)(o_tmp + 6*32 + 1*32),
              addr, o_addr,
              tmp, (short)(o_tmp + 6*32 + 1*32),
              tmp, (short)(o_tmp + 6*32 + 2*32),
              tmp, (short)(o_tmp + 64));

        /* Pull up the 67th leaf, combine */
        addr[ADDR_TREE_INDEX_LSBYTE] = 64 >>> 2;
        addr[ADDR_TREE_HEIGHT_LSBYTE] = 1;
        hashh(tmp, (short)(o_tmp + 6*32 + 1*32),
              addr, o_addr,
              tmp, (short)(o_tmp + 6*32 + 1*32),
              tmp, (short)(o_tmp + 6*32 + 3*32),
              tmp, (short)(o_tmp + 64));

        /* Pull up the result to the top of the tree, combine with sub-root */
        addr[ADDR_TREE_INDEX_LSBYTE] = 0;
        addr[ADDR_TREE_HEIGHT_LSBYTE] = 6;
        hashh(root, o_root,
              addr, o_addr,
              tmp, (short)(o_tmp + 6*32),
              tmp, (short)(o_tmp + 6*32 + 1*32),
              tmp, (short)(o_tmp + 64));
    }

    /* Computes auth path and root from leafs, authenticating leaf at leaf_idx,
       expecting an address that contains the layer and tree index set,
       and a tmp array that has space for (H / D + 1) * N + 128 bytes.
       outputs (H / D) * N bytes to auth, and N bytes to root. */
    public void authAndRoot(byte[] auth, short o_auth,
                            byte[] root, short o_root,
                            byte[] leafs, short o_leafs,
                            short leaf_idx,
                            byte[] addr, short o_addr,
                            byte[] tmp, short o_tmp) {
        short offset = 0;
        short idx;
        short treeIdx;

        /* Reset everything except layer and tree */
        Util.arrayFillNonAtomic(addr, (short)(o_addr + ADDR_TYPE_LSBYTE + 1),
                                (short)16, (byte)0);
        addr[ADDR_TYPE_LSBYTE] = ADDRTYPE_HASHTREE;

        /* Ensure tmp contains leading zeroes; precondition for hashh */
        Util.arrayFillNonAtomic(tmp, (short)(o_tmp + (H/D + 1) * N),
                                (short)31, (byte)0);

        for (idx = 0; idx < (1 << (H/D)); idx++) {
            /* Add the next leaf node to the stack. */
            Util.arrayCopyNonAtomic(leafs, (short)(o_leafs + N*idx),
                                    tmp, (short)(o_tmp + offset*N), N);
            tmpShorts[offset] = 0;
            offset++;

            /* If this is a node we need for the auth path.. */
            if ((leaf_idx ^ 0x1) == idx) {
                Util.arrayCopyNonAtomic(tmp, (short)(o_tmp + (offset - 1)*N),
                                        auth, o_auth, N);
            }

            /* While the top-most nodes are of equal height.. */
            while (offset >= 2 && tmpShorts[(short)(offset - 1)] == tmpShorts[(short)(offset - 2)]) {
                /* Compute index of the new node, in the next layer. */
                treeIdx = (short)(idx >>> (tmpShorts[(short)(offset - 1)] + 1));

                /* Hash the top-most nodes from the stack together. */
                /* Note that tree height is the 'lower' layer, even though we use
                   the index of the new node on the 'higher' layer. This follows
                   from the fact that we address the hash function calls. */
                addr[ADDR_TREE_HEIGHT_LSBYTE] = (byte)tmpShorts[(short)(offset - 1)];
                addr[ADDR_TREE_INDEX_LSBYTE] = (byte)treeIdx;

                /* Overwrite one of the inputs, pop the other off the stack */
                hashh(tmp, (short)(o_tmp + (offset - 2)*N),
                      addr, o_addr,
                      tmp, (short)(o_tmp + (offset - 2)*N),
                      tmp, (short)(o_tmp + (offset - 1)*N),
                      /* There are at most H/D + 1 nodes on the stack */
                      tmp, (short)(o_tmp + (H/D + 1) * N));
                offset--;
                /* Note that the top-most node is now one layer higher. */
                tmpShorts[(short)(offset - 1)]++;

                /* If this is a node we need for the auth path.. */
                if ((short)((leaf_idx >>> tmpShorts[(short)(offset - 1)]) ^ 0x1) == treeIdx) {
                    Util.arrayCopyNonAtomic(tmp, (short)(o_tmp + (offset - 1)*N),
                                            auth, (short)(o_auth + tmpShorts[(short)(offset - 1)]*N), N);
                }
            }
        }
        Util.arrayCopyNonAtomic(tmp, o_tmp, root, o_root, N);
    }

    /* Converts an index consisting of two 15-bit positive shorts to 4 bytes.
       This is required for the signature, but also for addresses. */
    private void indexToBytes(byte[] out, short o_out, short high, short low) {
        Util.setShort(out, o_out, high);
        Util.setShort(out, (short)(o_out + 2), low);
        /* Carry a bit from the 2nd to the 3rd byte */
        out[(short)(o_out + 2)] |= 0xFF & ((out[(short)(o_out + 1)] & 1) << 7);
        out[(short)(o_out + 1)] >>>= 1;
        /* Carry a bit from the 1st to the 2nd byte */
        out[(short)(o_out + 1)] |= 0xFF & ((out[o_out] & 1) << 7);
        out[o_out] >>>= 1;
        /* Note that we only need to carry one bit; the other irregular bit is
           the most significant bit of the 1st byte, and will remain zero. */
    }

    /* Initial method to start creating a signature. Expects the signing state
       to be in the zero-state.
       Reads the message from the APDU, hashes it and returns the first parts
       of the signature: indexBytes and R. */
    public void signInit(APDU apdu, byte[] tmp, short o_tmp) {
        if (signingState != 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short messageLength = storeAPDU(apdu, tmp, (short)(o_tmp + 32));
        byte[] buffer = apdu.getBuffer();

        /* Initialize the index used for the current signature */
        signingIdxHigh = indexHigh;
        signingIdxLow = indexLow;

        /* Increment the index to be used for the next signature; this must be
           done before actually signing, to ensure one signature per leaf. */
        if (indexLow == 32767) {
            /* Carry into indexHigh when it would otherwise overflow 15 bits */
            indexHigh++;
            /* Worst case, if we break off here, we skip 2^15 signatures rather
               than redoing 2^15 with the same indexHigh */
            indexLow = 0;
        }
        else {
            indexLow++;
        }

        short indexBytes = (H + 7) / 8;
        /* Convert the shorts to consecutive bytes */
        indexToBytes(buffer, (short)0, signingIdxHigh, signingIdxLow);

        /* Compute R = PRF(index_as_32_bytes, key) */
        Util.arrayFillNonAtomic(tmp, o_tmp, (short)31, (byte)0);
        tmp[(short)(o_tmp + 31)] = DOMAINSEP_PRF;
        md.reset();
        md.update(tmp, o_tmp, (short)32);
        md.update(secretKey, (short)32, N);
        /* Since the first 31 bytes are zero, this sets tmp to [28x zero, idx] */
        indexToBytes(tmp, (short)(o_tmp + 28), signingIdxHigh, signingIdxLow);
        md.doFinal(tmp, o_tmp, (short)32, buffer, (short)4);

        /* Compute the message hash = H(R, ROOT, index, message) */
        Util.arrayFillNonAtomic(tmp, o_tmp, (short)31, (byte)0);
        tmp[(short)(o_tmp + 31)] = DOMAINSEP_HASH;
        md.update(tmp, o_tmp, (short)32);  /* Domain separator */
        md.update(buffer, (short)4, N);  /* R */
        md.update(publicKey, (short)0, N);  /* ROOT */
        /* Since the first 31 bytes are zero, this sets tmp to [28x zero, idx] */
        indexToBytes(tmp, (short)(o_tmp + 28), signingIdxHigh, signingIdxLow);
        md.update(tmp, o_tmp, (short)32);  /* Idx */
        md.doFinal(tmp, (short)(o_tmp + 32), messageLength, signingRoot, (short)0);  /* Message */

        apdu.setOutgoing();
        signingState++;
        /* indexBytes bytes for the index, 32 bytes for R */
        apdu.setOutgoingLength((short)(N + indexBytes));
        /* Skip some bytes if indexBytes should be less than the max. 4 */
        apdu.sendBytes((short)(4 - indexBytes), (short)(N + indexBytes));
    }

    /* Computes the low 15 bits of a tree index based on a leaf index;
       effectively performs a division by 2^(H/D) */
    public short deriveTreeIdxLow(short idxHigh, short idxLow) {
        return (short)((idxLow >>> (H/D) + (32767 & (idxHigh << (15 - H/D)))));
    }

    /* Computes the high 15 bits of a tree index based on a leaf index;
       since its result is strictly smaller, only requires high part of idx;
       effectively performs a division by 2^(H/D) */
    public short deriveTreeIdxHigh(short idxHigh) {
        return (short)(idxHigh >>> (H/D));
    }

    /* Sets the tree field based on a leaf index. */
    public void setTreeAddrFromLeaf(byte[] addr, short o_addr, short idxHigh, short idxLow) {
        indexToBytes(addr, (short)(o_addr + ADDR_TREE_LOW_LSBYTE - 3),
                     deriveTreeIdxHigh(idxHigh),
                     deriveTreeIdxLow(idxHigh, idxLow));
        /* Can safely ignore ADDR_TREE_HIGH_LSBYTE since we assume H <= 30 */
    }

    /* Expects signingState-1 to be [0-8] mod 16, which indicates the specific
       chains that are expected. This includes the checksum chains.
       TODO requirements on tmp are unclear. */
    public void signWOTS(APDU apdu, byte[] tmp, short o_tmp) {
        if (signingState < 1 || ((signingState - 1) & 15) > 8) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        /* Figure out what the current leaf node was */
        short currLow = (short)(indexLow - 1);
        short currHigh = indexHigh;
        short currLayer = (short)((short)(signingState - 1) >>> 4);

        /* If it underflowed, carry from currHigh. */
        if (currLow == -1) {
            currLow = 32767;
            currHigh -= 1;
        }

        /* Send 8x32 bytes for normal chains, 3x32 for the checksum */
        /* jcardsim breaks for some reason when Le = 0x00 implying 256 bytes,
           so change this to 255 when running in jcardsim for debugging. */
        short outlen = (short)((((signingState - 1) & 15) == 8) ? 96 : 256);
        apdu.setOutgoing();
        apdu.setOutgoingLength(outlen);

        /* It could be that we have previously cached this signature */
        /* The first signature is exceptional; there is no previous index,
           so we must be careful wrt the result of `firstSameLayer`. */
        if (!(indexLow == 1 && indexHigh == 0 && currLayer == 0)) {
            if ((indexLow == 1 && indexHigh == 0 && currLayer > 0) ||
                currLayer >= firstSameLayer(currHigh, currLow)) {
                signingState++;
                apdu.sendBytesLong(
                    WOTSSignatures,
                    (short)(((signingState - 2) & 15) * 256 + (currLayer-1) * WOTS_LEN * N),
                    outlen);
                return;
            }
        }

        /* Use tmp as [address] [ots seed] [chainseed] [31x 0, DOMAINSEP] */

        Util.arrayFillNonAtomic(tmp, o_tmp, (short)32, (byte)0);
        /* Set subtree address */
        tmp[(short)(o_tmp + ADDR_LAYER_LSBYTE)] = (byte)currLayer;
        setTreeAddrFromLeaf(tmp, o_tmp, signingIdxHigh, signingIdxLow);

        tmp[(short)(o_tmp + ADDR_TYPE_LSBYTE)] = ADDRTYPE_OTS;

        /* Since we assume that H/D <= 15, we can freely use only the low short
           for the OTS leaf index */
        /* The -3 is needed because indexToBytes writes 4 bytes. */
        /* Mask out any bits that exceed the current tree */
        indexToBytes(tmp, (short)(ADDR_OTS_LSBYTE - 3), (short)0,
                     (short)(signingIdxLow & ((1 << (H/D)) - 1)));

        WOTSGetSeed(tmp, (short)(o_tmp + 32),
                    tmp, o_tmp,
                    tmp, (short)(o_tmp + 96));

        /* tmp now contains [address] [ots seed] [??] [31x 0, DOMAINSEP_PRF] */

        /* Begin signing the value in signingRoot using WOTS */

        /* First compute the lengths of the chains we need.
           TODO: in principle each signing stage only needs a portion of these,
           but splitting the computation is a hassle. No real speed gain. */
        chainLengths(tmpShorts, signingRoot, tmp, (short)(o_tmp + 64));

        /* Compute which chain is the starting chain */
        short chain = (short)(8 * ((signingState - 1) & 15));

        /* In principle 8 chains = 256 bytes per APDU */
        for (short i = 0; i < 8; i++) {
            /* Since the checksum is not a multiple of 8, the last block of
               chains must terminate early */
            if ((short)(chain + i) >= WOTS_LEN) {
                break;
            }

            WOTSComputeChainseed(tmp, (short)(o_tmp + 64),
                                 tmp, (short)(o_tmp + 96),
                                 tmp, (short)(o_tmp + 32),
                                 (byte)(chain + i));

            tmp[(short)(o_tmp + ADDR_CHAIN_LSBYTE)] = (byte)(chain + i);
            /* tmp now contains: [address] [ots seed] [chainseed]
                                 [31x 0, DOMAINSEP_PRF]
                                 [reservation for f in WOTSChain]
                                 [.. chain output..] */
            if (currLayer == 0) {
                WOTSChain(tmp, (short)(o_tmp + 160 + i*32),
                          tmp, o_tmp,
                          tmp, (short)(o_tmp + 64),
                          tmp, (short)(o_tmp + 96),
                          tmpShorts[(short)(chain + i)]);
            }
            else {
                WOTSChain(WOTSSignatures, (short)(((signingState - 1) & 15) * 256 + i*32 + (currLayer-1) * WOTS_LEN * N),
                          tmp, o_tmp,
                          tmp, (short)(o_tmp + 64),
                          tmp, (short)(o_tmp + 96),
                          tmpShorts[(short)(chain + i)]);
            }
        }
        signingState++;
        if (currLayer == 0) {
            apdu.sendBytesLong(
                tmp,
                (short)(o_tmp + 160),
                outlen);
        }
        else{
            apdu.sendBytesLong(
                WOTSSignatures,
                (short)(((signingState - 2) & 15) * 256 + (currLayer-1) * WOTS_LEN * N),
                outlen);
        }
    }

    /* Expects signingState-1 to be 9 mod 16. Computes the authentication path
       that is necessary to authenticate the WOTS public key. */
    public void signAuthPath(APDU apdu, byte[] tmp, short o_tmp) {
        if (((signingState - 1) & 15) != 9) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        /* Since we assume that H/D <= 15, we can freely use only the low short
           for the OTS leaf index */
        /* Mask out any bits that exceed the current tree */
        short leafIdx = (short)(signingIdxLow & ((1 << (H/D)) - 1));
        /* Compute whether this is an even or odd tree, which indicates the
           location of precomputed leaf nodes in the `nodes` array */
        short treeParity = (short)(deriveTreeIdxLow(signingIdxHigh, signingIdxLow) & 0x1);

        /* Initialize the address */
        Util.arrayFillNonAtomic(tmp, o_tmp, (short)32, (byte)0);
        /* Set subtree address */
        tmp[(short)(o_tmp + ADDR_LAYER_LSBYTE)] = (byte)((short)(signingState - 1) >>> 4);
        setTreeAddrFromLeaf(tmp, o_tmp, signingIdxHigh, signingIdxLow);

        /* Store the authentication path in next H/D * N bytes, in tmp;
           use the remaining (H / D + 1) * N + 128 bytes as temporary space
           for the authAndRoot function */
        authAndRoot(tmp, (short)(o_tmp + 32), signingRoot, (short)0,
                    /* The relevant leaf nodes have been precomputed */
                    nodes, (short)(N * (D*treeParity + tmp[ADDR_LAYER_LSBYTE]) * (1 << (H / D))),
                    leafIdx,
                    tmp, o_tmp,
                    tmp, (short)(o_tmp + (H / D) * N + 32));

        /* Move the signing index one layer up */
        signingIdxLow = deriveTreeIdxLow(signingIdxHigh, signingIdxLow);
        signingIdxHigh = deriveTreeIdxHigh(signingIdxHigh);

        /* If this was the topmost layer.. */
        if ((short)((short)(signingState - 1) >>> 4) == D - 1) {
            signingState++;  /* Continue to preparation step */
        }
        else {
            signingState += (short)7;  /* Skip over assigned states */
        }

        /* Output the authentication path */
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)(N * H / D));
        apdu.sendBytesLong(tmp, (short)(o_tmp + 32), (short)(N * H / D));
    }

    /* Returns the first layer on which the index and its predecessor converge.
       Yields undefined results for input (0, 0), i.e. the first index. */
    public short firstSameLayer(short idxHigh, short idxLow) {
        /* Roll back one index, to see which leafs have changed */
        short prevLow = (short)(idxLow - 1);
        short prevHigh = idxHigh;
        short i;

        /* If it underflowed, carry from prevHigh. prevHigh also underflows
           for the first signature; one should ignore this case. */
        if (prevLow == -1) {
            prevLow = 32767;
            prevHigh -= 1;
        }

        for (i = 1; i < D; i++) {
            idxLow = deriveTreeIdxLow(idxHigh, idxLow);
            idxHigh = deriveTreeIdxHigh(idxHigh);
            prevLow = deriveTreeIdxLow(prevHigh, prevLow);
            prevHigh = deriveTreeIdxHigh(prevHigh);

            if (idxLow == prevLow && idxHigh == prevHigh) {
                return i;
            }
        }
        return D;
    }

    /* Computes a leaf node in the 'next' tree on every layer where a leaf
       node was just consumed by the signature we created. This implies the
       bottom layer always gets one leaf computation, the next layer once every
       two signatures, etc.
       This function is not necessary for completeness of the signature, but
       it is enforced before the next signature is created. That is not
       strictly necessary, as there is roughly H/D signatures leeway, but
       simplifies the implementation. */
    public void signPrepNext(APDU apdu, byte[] tmp, short o_tmp) {
        if (((signingState - 1) & 15) != 10) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short i;

        /* Compute the index of the current signature (note that indexLow has
           already been incremented, and signingLow has been destroyed). */
        short currLow = (short)(indexLow - 1);
        short currHigh = indexHigh;
        short nextLow, nextHigh;
        short nextTreeParity;

        /* If it underflowed, carry from currHigh. */
        if (currLow == -1) {
            currLow = 32767;
            currHigh -= 1;
        }

        short unchangedLayer = firstSameLayer(currHigh, currLow);

        /* Prepare on every layer, except for the topmost single tree */
        for (i = 0; i < D - 1; i++) {
            /* If this is the very first index, we disregard prev entirely;
               the next trees are empty on all layers, so we want to compute
               a leaf node for each. */
            if (!(indexLow == 1 && indexHigh == 0)) {
                /* If the current and previous index have converged, none of
                   the indices on the next layers will have changed, so we do
                   not need to compute new leafs. */
                if (i == unchangedLayer) {
                    break;
                }
            }

            /* If 'currLow + tree width' fits within 15 bits.. (comparing in
               this way is necessary to avoid an overflow) */
            if ((short)(32767 - currLow) >= 1 << (H/D)) {
                nextLow = (short)(currLow + (1 << (H/D)));
                nextHigh = currHigh;
            }
            else {
                /* Otherwise loop around mod 2^15. Again avoid overflow into
                   signed integers. */
                nextLow = (short)((1 << (H/D)) - (32767 - currLow));
                nextHigh = (short)(currHigh + 1);
            }

            /* Initialize the address */
            Util.arrayFillNonAtomic(tmp, o_tmp, (short)32, (byte)0);
            tmp[(short)(o_tmp + ADDR_LAYER_LSBYTE)] = (byte) i;
            setTreeAddrFromLeaf(tmp, o_tmp, nextHigh, nextLow);

            /* Since we assume that H/D <= 15, we can freely use only the low
               short for the OTS leaf index */
            /* Mask out any bits that exceed the current tree */
            short leafIdx = (short)(nextLow & ((1 << (H/D)) - 1));
            Util.setShort(tmp, (short)(o_tmp + ADDR_OTS_LSBYTE - 1), leafIdx);

            /* Move the indices one layer up */
            currLow = deriveTreeIdxLow(currHigh, currLow);
            currHigh = deriveTreeIdxHigh(currHigh);

            /* Parity of next tree is inverse of current tree parity */
            nextTreeParity = (short)(1 - (currLow & 0x1));

            WOTSLeafGen(nodes, (short)(N * ((nextTreeParity*D + i) * (1 << (H / D)) + leafIdx)),
                               tmp, o_tmp, tmp, (short)(o_tmp + 32));
        }

        signingState = 0;
        /* The index has already been incremented in signInit; waiting until
           here would have been a security risk. */
    }

    /* Initializes the nodes buffer to contain the leafs of all 0th trees.
       Expects tmp to have 32 bytes for the address and 13*N bytes for WOTS.
       This is a very costly operation. */
    public void initializeNodes(byte[] tmp, short o_tmp) {
        short i, leafIdx;

        /* Compute the leafs of all initial trees on all layers */
        for (i = 0; i < D; i++) {
            for (leafIdx = 0; leafIdx < 1 << (H / D); leafIdx++) {
                /* Initialize the address */
                Util.arrayFillNonAtomic(tmp, o_tmp, (short)32, (byte)0);
                tmp[(short)(o_tmp + ADDR_LAYER_LSBYTE)] = (byte) i;
                /* The tree field can be left at zero, since this concerns the
                   first tree on each layer. */
                Util.setShort(tmp, (short)(o_tmp + ADDR_OTS_LSBYTE - 1), leafIdx);
                WOTSLeafGen(nodes, (short)(N * (i * (1 << (H / D)) + leafIdx)),
                            tmp, o_tmp, tmp, (short)(o_tmp + 32));
            }
        }
    }

    /* Output ROOT and PUBSEED */
    public void getPublicKey(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)64);
        apdu.sendBytesLong(publicKey, (short)0, (short)64);
    }

    /* Finalizes a keypair after it has been seeded and supplied with
       precomputed leaf nodes. This is separated because several different
       approaches can be taken w.r.t. seeding and precomputing. */
    private void finalizeKeypair(byte[] tmp, short o_tmp) {
        indexHigh = 0;
        indexLow = 0;

        /* The tree field can be left at zero, since it's the first tree */
        Util.arrayFillNonAtomic(tmp, o_tmp, (short)32, (byte)0);
        tmp[(short)(o_tmp + ADDR_LAYER_LSBYTE)] = (byte)(D - 1);

        /* Use the leaf nodes of the topmost tree to compute the ROOT */
        /* Using the first 32 bytes of tmp for the address;
                 the next H/D * N bytes of tmp for auth path, ignoring result;
                 the next (H / D + 1) * N + 128 bytes as tmp */
        authAndRoot(tmp, (short)(o_tmp + 32), publicKey, (short)0,
                    nodes, (short)(N * ((D - 1) * (1 << (H / D)))),
                    (short)0,
                    tmp, o_tmp,
                    tmp, (short)(o_tmp + (H / D) * N + 32));

        signingState = 0;
    }

    /* Generates a fresh keypair on the card, and initializes for signing */
    public void generateKeypair(APDU apdu, byte[] tmp, short o_tmp, RandomData rng) {
        rng.generateData(secretKey, (short)0, (short)64);  /* SKSEED + SKPRF */
        rng.generateData(publicKey, (short)32, (short)32);  /* PUBSEED */

        /* Precompute leafs for all first trees */
        initializeNodes(tmp, o_tmp);

        /* Complete initialization */
        finalizeKeypair(tmp, o_tmp);
    }

    public void initializeKeys(APDU apdu, byte[] tmp, short o_tmp) {
        /* Ensure that we're not actually ready to sign now, since nodes are
           not initialized properly (anymore). */
        signingState = -3;
        nodeBytesReceived = 0;
        WOTSBytesReceived = 0;
        nodesSent = 0;

        storeAPDU(apdu, tmp, o_tmp);

        Util.arrayCopyNonAtomic(tmp, o_tmp, secretKey, (short)0, (short)64);
        /* Note that the root is skipped and will be computed on the card */
        Util.arrayFillNonAtomic(publicKey, (short)0, (short)64, (byte)0); // DEBUG
        Util.arrayFillNonAtomic(nodes, (short)0, (short)(N * D * (1 << (H / D))), (byte)0); // DEBUG
        Util.arrayCopyNonAtomic(tmp, (short)(o_tmp + 64), publicKey, (short)32, (short)32);
    }

    /* Initializes the card using randomness generated outside the card. This
       may be useful for situations where there are additional requirements
       on the security of the RNG. Expects 3 seeds: SKSEED, SKPRF, PUBSEED */
    public void initializeWithKeypair(APDU apdu, byte[] tmp, short o_tmp) {
        initializeKeys(apdu, tmp, o_tmp);

        /* Precompute leafs for all first trees */
        initializeNodes(tmp, o_tmp);

        /* Complete initialization */
        finalizeKeypair(tmp, o_tmp);
    }

    public void initializeWithNodes(APDU apdu, byte[] tmp, short o_tmp) {
        /* Can only upload nodes if we're setting up a new key */
        if (signingState != -3) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short bytesReceived = storeAPDU(apdu, tmp, o_tmp);
        short bytesNeeded = (short)(N * D * (1 << (H / D)) - nodeBytesReceived);

        if (bytesReceived < bytesNeeded) {
            Util.arrayCopyNonAtomic(tmp, o_tmp, nodes, nodeBytesReceived, bytesReceived);
            nodeBytesReceived += bytesReceived;
        }
        else {
            Util.arrayCopyNonAtomic(tmp, o_tmp, nodes, nodeBytesReceived, bytesNeeded);
            nodeBytesReceived += bytesNeeded;
            /* Continue to uploading WOTS signatures */
            signingState = -2;
        }
    }

    public void initializeWOTS(APDU apdu, byte[] tmp, short o_tmp) {
        /* Can only upload WOTS signatures if we've set up nodes */
        if (signingState != -2) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short bytesReceived = storeAPDU(apdu, tmp, o_tmp);
        short bytesNeeded = (short)((WOTS_LEN * N * (D - 1)) - WOTSBytesReceived);

        if (bytesReceived < bytesNeeded) {
            Util.arrayCopyNonAtomic(tmp, o_tmp, WOTSSignatures, WOTSBytesReceived, bytesReceived);
            WOTSBytesReceived += bytesReceived;
        }
        else {
            Util.arrayCopyNonAtomic(tmp, o_tmp, WOTSSignatures, WOTSBytesReceived, bytesNeeded);
            WOTSBytesReceived += bytesNeeded;
            /* Complete initialization */
            finalizeKeypair(tmp, o_tmp);
        }
    }

    public static short nodesSent = 0;

    /* For debugging purposes, get the nodes */
    public void getNodes(APDU apdu) {
        nodesSent++;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)32);
        apdu.sendBytesLong(nodes, (short)(32 * (nodesSent - 1)), (short)32);
    }

    public static short storeAPDU(APDU apdu, byte[] dest, short offset) {
        short bytesRead = apdu.setIncomingAndReceive();
        /* Truncate to a byte to prevent sign extension. The jcardsim
           implementation returns 0xFF80 when really it means 0x80. */
        short numBytes = (short)(0xFF & apdu.getIncomingLength());

        byte[] buffer = apdu.getBuffer();
        short pos = 0;

        // Since numBytes may exceed the guaranteed CDATA buffer of 128 bytes
        while (pos < numBytes) {
            Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), dest, (short)(pos + offset), bytesRead);
            pos += bytesRead;
            bytesRead = apdu.receiveBytes(apdu.getOffsetCdata());
        }
        return numBytes;
    }
}
