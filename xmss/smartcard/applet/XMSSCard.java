package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.security.MessageDigest;

public class XMSSCard extends Applet {

    public static final byte CLA = (byte)0x80;
    public static final byte INS_XMSS_KEYGEN = (byte)0x50;
    public static final byte INS_XMSS_INIT_KEYS = (byte)0x51;
    public static final byte INS_XMSS_GET_PK = (byte)0x52;
    public static final byte INS_XMSS_SIGN_INIT = (byte)0x53;
    public static final byte INS_XMSS_SIGN_WOTS = (byte)0x54;
    public static final byte INS_XMSS_SIGN_AUTHPATH = (byte)0x55;
    public static final byte INS_XMSS_SIGN_PREP = (byte)0x56;
    public static final byte INS_XMSS_INIT_KEYS_NO_COMPUTE = (byte)0x57;
    public static final byte INS_XMSS_INIT_NODES = (byte)0x58;
    public static final byte INS_XMSS_INIT_WOTS = (byte)0x59;

    /* For debugging purposes; there is no functional reason for this, but also
       no additional security risk. */
    public static final byte INS_XMSS_GET_NODES = (byte)0x5F;

    private final MessageDigest digestSHA256;
    private final XMSS xmss;
    private final RandomData randomData;
    private final byte[] tmp;

    private XMSSCard() {
        tmp = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        digestSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        xmss = new XMSS(digestSHA256);
        register();
    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new XMSSCard();
    }

    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        /* If it's the wrong application class.. */
        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt((short)0x42);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_XMSS_KEYGEN:
                xmss.generateKeypair(apdu, tmp, (short)0, randomData);
                break;
            case INS_XMSS_INIT_KEYS:
                xmss.initializeWithKeypair(apdu, tmp, (short)0);
                break;
            case INS_XMSS_INIT_KEYS_NO_COMPUTE:
                xmss.initializeKeys(apdu, tmp, (short)0);
                break;
            case INS_XMSS_INIT_NODES:
                xmss.initializeWithNodes(apdu, tmp, (short)0);
                break;
            case INS_XMSS_INIT_WOTS:
                xmss.initializeWOTS(apdu, tmp, (short)0);
                break;
            case INS_XMSS_GET_NODES:
                xmss.getNodes(apdu);
                break;
            case INS_XMSS_GET_PK:
                xmss.getPublicKey(apdu);
                break;
            case INS_XMSS_SIGN_INIT:
                xmss.signInit(apdu, tmp, (short)0);
                break;
            case INS_XMSS_SIGN_WOTS:
                xmss.signWOTS(apdu, tmp, (short)0);
                break;
            case INS_XMSS_SIGN_AUTHPATH:
                xmss.signAuthPath(apdu, tmp, (short)0);
                break;
            case INS_XMSS_SIGN_PREP:
                xmss.signPrepNext(apdu, tmp, (short)0);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
