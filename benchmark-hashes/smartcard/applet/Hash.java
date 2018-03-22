package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.security.MessageDigest;

public class Hash extends Applet {

    public static final byte CLA = (byte)0x80;

    private final MessageDigest md;
    private final byte[] tmp;

    private Hash() {
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        tmp = JCSystem.makeTransientByteArray((short)512, JCSystem.CLEAR_ON_DESELECT);
        register();
    }

    public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
        new Hash();
    }

    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }

        short i;

        for (i = 0; i < 512; i++) {
            md.doFinal(tmp, (short)32, (short)128, tmp, (short)0);
        }
    }
}
