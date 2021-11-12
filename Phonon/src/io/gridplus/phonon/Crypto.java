package io.gridplus.phonon;

import javacard.framework.JCSystem;
import javacard.framework.Util;
//import javacard.security.*;
//import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacard.security.AESKey;
import javacardx.crypto.Cipher;
//import javacard.security.ECPublicKey;
//import javacard.security.KeyPair;
import javacard.security.CryptoException;
import javacard.security.HMACKey;

/**
 * Crypto utilities, mostly BIP32 related. The init method must be called during application installation. This class
 * is not meant to be instantiated.
 */
public class Crypto {
    final static public short AES_BLOCK_SIZE = 16;

    final static short KEY_SECRET_SIZE = 32;
    final static private short HMAC_BLOCK_SIZE = (short) 128;

    // The below 5 objects can be accessed anywhere from the entire applet
    RandomData random;
    KeyAgreement ecdh;
    MessageDigest sha256;
    MessageDigest sha512;
    Cipher aesCbcIso9797m2;

    private Signature hmacSHA512;
    private HMACKey hmacKey;

    private byte[] hmacBlock;

    Crypto() {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        aesCbcIso9797m2 = Cipher.getInstance(Cipher.ALG_AES_CBC_ISO9797_M2, false);

        try {
            hmacSHA512 = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
            hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, KEY_SECRET_SIZE, false);
        } catch (CryptoException e) {
            hmacSHA512 = null;
            hmacBlock = JCSystem.makeTransientByteArray(HMAC_BLOCK_SIZE, JCSystem.CLEAR_ON_RESET);
        }

    }


    /**
     * Modulo addition of two 256-bit numbers.
     *
     * @param a      the a operand
     * @param aOff   the offset of the a operand
     * @param b      the b operand
     * @param bOff   the offset of the b operand
     * @param n      the modulo
     * @param nOff   the offset of the modulo
     * @param out    the output buffer
     * @param outOff the offset in the output buffer
     */
    private void addm256(byte[] a, short aOff, byte[] b, short bOff, byte[] n, short nOff, byte[] out, short outOff) {
        if ((add256(a, aOff, b, bOff, out, outOff) != 0) || (ucmp256(out, outOff, n, nOff) > 0)) {
            sub256(out, outOff, n, nOff, out, outOff);
        }
    }

    /**
     * Compares two 256-bit numbers. Returns a positive number if a > b, a negative one if a < b and 0 if a = b.
     *
     * @param a    the a operand
     * @param aOff the offset of the a operand
     * @param b    the b operand
     * @param bOff the offset of the b operand
     * @return the comparison result
     */
    private short ucmp256(byte[] a, short aOff, byte[] b, short bOff) {
        short ai, bi;
        for (short i = 0; i < 32; i++) {
            ai = (short) (a[(short) (aOff + i)] & 0x00ff);
            bi = (short) (b[(short) (bOff + i)] & 0x00ff);

            if (ai != bi) {
                return (short) (ai - bi);
            }
        }

        return 0;
    }

    /**
     * Checks if the given 256-bit number is 0.
     *
     * @param a    the a operand
     * @param aOff the offset of the a operand
     * @return true if a is 0, false otherwise
     */
    private boolean isZero256(byte[] a, short aOff) {
        boolean isZero = true;

        for (short i = 0; i < (byte) 32; i++) {
            if (a[(short) (aOff + i)] != 0) {
                isZero = false;
                break;
            }
        }

        return isZero;
    }

    /**
     * Addition of two 256-bit numbers.
     *
     * @param a      the a operand
     * @param aOff   the offset of the a operand
     * @param b      the b operand
     * @param bOff   the offset of the b operand
     * @param out    the output buffer
     * @param outOff the offset in the output buffer
     * @return the carry of the addition
     */
    private short add256(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        short outI = 0;
        for (short i = 31; i >= 0; i--) {
            outI = (short) ((short) (a[(short) (aOff + i)] & 0xFF) + (short) (b[(short) (bOff + i)] & 0xFF) + outI);
            out[(short) (outOff + i)] = (byte) outI;
            outI = (short) (outI >> 8);
        }
        return outI;
    }

    /**
     * Subtraction of two 256-bit numbers.
     *
     * @param a      the a operand
     * @param aOff   the offset of the a operand
     * @param b      the b operand
     * @param bOff   the offset of the b operand
     * @param out    the output buffer
     * @param outOff the offset in the output buffer
     * @return the carry of the subtraction
     */
    private short sub256(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        short outI = 0;

        for (short i = 31; i >= 0; i--) {
            outI = (short) ((short) (a[(short) (aOff + i)] & 0xFF) - (short) (b[(short) (bOff + i)] & 0xFF) - outI);
            out[(short) (outOff + i)] = (byte) outI;
            outI = (short) (((outI >> 8) != 0) ? 1 : 0);
        }

        return outI;
    }
}
