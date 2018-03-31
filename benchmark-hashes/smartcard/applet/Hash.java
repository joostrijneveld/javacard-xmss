package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;

public class Hash extends Applet {

    public static final byte CLA = (byte)0x80;

    private final MessageDigest md;
    private final Cipher aes;
    private final AESKey key;
    private final byte[] tmp;
    private final RandomData randomData;

    private Hash() {
        tmp = JCSystem.makeTransientByteArray((short)1024, JCSystem.CLEAR_ON_DESELECT);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aes = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        randomData.generateData(tmp, (short)0, (short)1024);
        key.setKey(tmp, (short)0);
        aes.init(key, Cipher.MODE_ENCRYPT);

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

        for (i = 0; i < 1000; i++) {
            // aes.doFinal(tmp, (short)0, (short)1024, tmp, (short)0);
            md.doFinal(tmp, (short)32, (short)32, tmp, (short)0);
        }
    }
}
