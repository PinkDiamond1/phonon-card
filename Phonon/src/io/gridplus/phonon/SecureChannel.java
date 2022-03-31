package io.gridplus.phonon;

//

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.KeyPair;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Implements all methods related to the secure channel as specified in the SECURE_CHANNEL.md document.
 */
public class SecureChannel {
    public static final boolean SECURE_CHANNEL_DEBUG = false;
    public static final boolean USE_CA_DEMO_KEY = false;

    public static final byte ID_CERTIFICATE_EMPTY = (byte) 0x00;
    public static final byte ID_CERTIFICATE_LOCKED = (byte) 0xFF;
    public static final short SC_KEY_LENGTH = 256;
    public static final short SC_SECRET_LENGTH = 32;
    public static final short PAIRING_KEY_LENGTH = SC_SECRET_LENGTH + 1;
    public static final short SC_BLOCK_SIZE = Crypto.AES_BLOCK_SIZE;
    public static final short SC_OUT_OFFSET = ISO7816.OFFSET_CDATA + (SC_BLOCK_SIZE * 2);
    public static final short SC_COUNTER_MAX = 100;
    public static final byte INS_OPEN_SECURE_CHANNEL = 0x10;
    public static final byte INS_MUTUALLY_AUTHENTICATE = 0x11;
    public static final byte INS_PAIR = 0x12;
    public static final byte INS_UNPAIR = 0x13;
    public static final byte INS_IDENTIFY_CARD = 0x14;
    public static final byte INS_LOAD_CERT = 0x15;
    public static final byte PAIR_P1_FIRST_STEP = 0x00;
    public static final byte PAIR_P1_LAST_STEP = 0x01;
    // cert = [permissions (2), certified pubKey (65), ECDSA signature from CA (74)]
    static final short ECDSA_MAX_LEN = 74;
    static final short PUBKEY_LEN = 65;
    // certificate format: [certType, certLen, permType, permLen, permissions(2), pubkeyType, pubkeyLen, pubkey(65), ecdsa sig (DER)]
    static final short CERTIFICATE_MAX_LEN = (short) (8 + PUBKEY_LEN + ECDSA_MAX_LEN);
    // Card identity key & certificate
    private final KeyPair idKeypair;
    //  public ECPublicKey verifyPublicKey;
    private final byte[] idCertificate;
    private final AESKey scEncKey;
    private final AESKey scMacKey;
    private final Signature scMac;
    private final KeyPair scKeypair;
    private final Signature eccSig;
    private final byte[] secret;
    private final AESKey CardscEncKey;
    private final AESKey CardscMacKey;
    private final byte[] SenderSalt;
    private final SECP256k1 localsecp256k1;
    
    public static final byte CARD_TO_CARD_NOT_INITIALIZED = 0x00;
    public static final byte CARD_TO_CARD_INIT_CARD_PAIR = 0x01;
    public static final byte CARD_TO_CARD_PAIR_1 = 0x02;
    public static final byte CARD_TO_CARD_PAIR_2 = 0x03;
    public static final byte CARD_TO_CARD_PAIRED = 0x04;
    
    public byte Card2CardStatus;

    /*
     * To avoid overhead, the pairing keys are stored in a plain byte array as sequences of 33-bytes elements. The first
     * byte is 0 if the slot is free and 1 if used. The following 32 bytes are the actual key data.
     */
    private final byte[] pairingKeys;
    private final Crypto crypto;
    private final byte[] DebugMasterPrivateKey = {0x00, (byte) 0x90, (byte) 0xf4, 0x55, 0x61, (byte) 0xb5, (byte) 0xa4, 0x3d, (byte) 0xa2, 0x7f, 0x35, 0x70, 0x63, 0x48, (byte) 0xbf, (byte) 0x86, (byte) 0xa4, 0x75, (byte) 0x9b, 0x23, (byte) 0x8a, 0x58, (byte) 0xa0, (byte) 0xed, (byte) 0xdb, 0x24, 0x2a, (byte) 0xa2, 0x64, (byte) 0xd0, (byte) 0xf0, 0x2f, 0x55};
    private final byte[] SafecardDevCAPubKey = {
            0x04,
            0x5c, (byte) 0xfd, (byte) 0xf7, 0x7a, 0x00, (byte) 0xb4, (byte) 0xb6, (byte) 0xb4,
            (byte) 0xa5, (byte) 0xb8, (byte) 0xbb, 0x26, (byte) 0xb5, 0x49, 0x7d, (byte) 0xbc,
            (byte) 0x7a, 0x4d, 0x01, (byte) 0xcb, (byte) 0xef, (byte) 0xd7, (byte) 0xaa, (byte) 0xea,
            (byte) 0xf5, (byte) 0xf6, (byte) 0xf8, (byte) 0xf8, (byte) 0x86, (byte) 0x59, 0x76, (byte) 0xe7,
            (byte) 0x94, 0x1a, (byte) 0xb0, (byte) 0xec, 0x16, 0x51, 0x20, (byte) 0x9c,
            0x44, 0x40, 0x09, (byte) 0xfd, 0x48, (byte) 0xd9, 0x25, (byte) 0xa1,
            0x7d, (byte) 0xe5, 0x04, 0x0b, (byte) 0xa4, 0x7e, (byte) 0xaf, 0x3f,
            0x5b, 0x51, 0x72, 0x0d, (byte) 0xd4, 0x0b, 0x2f, (byte) 0x9d,
    };
    // Prod cert CA Key
    private final byte[] SafecardProdCAPubKey = {
            0x04,
            0x77, (byte) 0x81, 0x6e, (byte) 0x8e, (byte) 0x83, (byte) 0xbb, 0x17, (byte) 0xc4,
            0x30, (byte) 0x9c, (byte) 0xc2, (byte) 0xe5, (byte) 0xaa, 0x13, 0x4c, 0x57,
            0x3a, 0x59, 0x43, 0x15, 0x49, 0x40, 0x09, 0x5a,
            0x42, 0x31, 0x49, (byte) 0xf7, (byte) 0xcc, 0x03, (byte) 0x84, (byte) 0xad,
            0x52, (byte) 0xd3, 0x3f, 0x1b, 0x4c, (byte) 0xd8, (byte) 0x9c, (byte) 0x96,
            0x7b, (byte) 0xf2, 0x11, (byte) 0xc0, 0x39, 0x20, 0x2d, (byte) 0xf3,
            (byte) 0xa7, (byte) 0x89, (byte) 0x9c, (byte) 0xb7, 0x54, 0x3d, (byte) 0xe4, 0x73,
            (byte) 0x8c, (byte) 0x96, (byte) 0xa8, 0x1c, (byte) 0xfd, (byte) 0xe4, (byte) 0xb1, 0x17,
    };
    public byte[] SenderidCertificate;
    public byte[] CardAESIV;
    public byte[] CardHash;
    public byte[] CardsessionKey;
    public byte[] CardSecret;
    byte[] CardAESCMAC;
    private boolean certEmpty; // EMPTY or LOCKED
    private byte[] pairingSecret;
    private short scCounter;
    private byte CardidCertStatus;
    private short CardidCertLen;
    private short preassignedPairingOffset = -1;
    private byte remainingSlots;
    private boolean mutuallyAuthenticated = false;


    /**
     * Instantiates a Secure Channel. All memory allocations (except pairing secret) needed for the secure channel are
     * performed here. The keypair used for the EC-DH algorithm is also generated here.
     *
     * @param pairingLimit
     * @param crypto
     * @param secp256k1
     */
    public SecureChannel(byte pairingLimit, Crypto crypto, SECP256k1 secp256k1) {
        this.crypto = crypto;
        localsecp256k1 = secp256k1;
        idKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        secp256k1.setCurveParameters((ECKey) idKeypair.getPrivate());
        secp256k1.setCurveParameters((ECKey) idKeypair.getPublic());
        idKeypair.genKeyPair();

        idCertificate = new byte[CERTIFICATE_MAX_LEN];
        certEmpty = true;
        CardidCertStatus = ID_CERTIFICATE_EMPTY;
        scMac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        eccSig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        scEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        scMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        CardscEncKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
        CardscMacKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

        scKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        secp256k1.setCurveParameters((ECKey) scKeypair.getPrivate());
        secp256k1.setCurveParameters((ECKey) scKeypair.getPublic());
        
     	scKeypair.genKeyPair();
        if( SECURE_CHANNEL_DEBUG == true)
        {
            ECPrivateKey idPrivateKey = (ECPrivateKey) scKeypair.getPrivate();
            idPrivateKey.setS(DebugMasterPrivateKey, (short) 0, (short) 32);
            byte[] PublicKeystr = new byte[70];
            short PublicKeyLength = localsecp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short) 0);
            ECPublicKey PublicKey = (ECPublicKey) scKeypair.getPublic();
            PublicKey.setW(PublicKeystr, (short) 0, PublicKeyLength);
        }

        secret = JCSystem.makeTransientByteArray((short) (SC_SECRET_LENGTH * 2), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        CardsessionKey = new byte[(short) (SC_SECRET_LENGTH * 2)];
        pairingKeys = new byte[(short) (PAIRING_KEY_LENGTH * pairingLimit)];
        remainingSlots = pairingLimit;

        CardAESIV = new byte[16];
        SenderSalt = new byte[32];
        CardHash = new byte[32];
        CardSecret = new byte[32];
        CardAESCMAC = JCSystem.makeTransientByteArray(SC_BLOCK_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    }


    /**
     *  Set the key to be a deterministic one for debugging purposes
     */
    public void SetDebugKey() {
        ECPrivateKey idPrivateKey = (ECPrivateKey) idKeypair.getPrivate();
        idPrivateKey.setS(DebugMasterPrivateKey, (short) 0, (short) 32);
        byte[] PublicKeystr = new byte[70];
        short PublicKeyLength = localsecp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short) 0);
        ECPublicKey PublicKey = (ECPublicKey) idKeypair.getPublic();
        PublicKey.setW(PublicKeystr, (short) 0, PublicKeyLength);
        idPrivateKey = (ECPrivateKey) scKeypair.getPrivate();
        idPrivateKey.setS(DebugMasterPrivateKey, (short) 0, (short) 32);
        PublicKeyLength = localsecp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short) 0);
        PublicKey = (ECPublicKey) scKeypair.getPublic();
        PublicKey.setW(PublicKeystr, (short) 0, PublicKeyLength);

    }

    /**
     * Initializes the SecureChannel instance with the pairing secret.
     *
     * @param aPairingSecret the pairing secret
     * @param off            the offset in the buffer
     */
    public void initSecureChannel(byte[] aPairingSecret, short off) {
        if (pairingSecret != null) return;

        pairingSecret = new byte[SC_SECRET_LENGTH];
        Util.arrayCopy(aPairingSecret, off, pairingSecret, (short) 0, SC_SECRET_LENGTH);
        if( SECURE_CHANNEL_DEBUG == true)
        {
            ECPrivateKey idPrivateKey = (ECPrivateKey) scKeypair.getPrivate();
            idPrivateKey.setS(DebugMasterPrivateKey, (short) 0, (short) 32);
            byte[] PublicKeystr = new byte[70];
            short PublicKeyLength = localsecp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short) 0);
            ECPublicKey PublicKey = (ECPublicKey) scKeypair.getPublic();
            PublicKey.setW(PublicKeystr, (short) 0, PublicKeyLength);
        }
        else
        	scKeypair.genKeyPair();
    }

    /**
     * Decrypts the content of the APDU by generating an AES key using EC-DH. Usable only with specific commands.
     *
     * @param apduBuffer the APDU buffer
     */
    public void oneShotDecrypt(byte[] apduBuffer) {
        crypto.ecdh.init(scKeypair.getPrivate());

        short off = (short) (ISO7816.OFFSET_CDATA + 1);
        try {
            crypto.ecdh.generateSecret(apduBuffer, off, apduBuffer[ISO7816.OFFSET_CDATA], secret, (short) 0);
            off = (short) (off + apduBuffer[ISO7816.OFFSET_CDATA]);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        scEncKey.setKey(secret, (short) 0);
        crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_DECRYPT, apduBuffer, off, SC_BLOCK_SIZE);
        off = (short) (off + SC_BLOCK_SIZE);

        apduBuffer[ISO7816.OFFSET_LC] = (byte) crypto.aesCbcIso9797m2.doFinal(apduBuffer, off, (short) ((short) (apduBuffer[ISO7816.OFFSET_LC] & 0xff) - off + ISO7816.OFFSET_CDATA), apduBuffer, ISO7816.OFFSET_CDATA);
    }

    /**
     * Processes the OPEN SECURE CHANNEL command.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    public void openSecureChannel(APDU apdu) {
        preassignedPairingOffset = -1;
        mutuallyAuthenticated = false;

        byte[] apduBuffer = apdu.getBuffer();

        short pairingKeyOff = checkPairingIndexAndGetOffset(apduBuffer[ISO7816.OFFSET_P1]);

        if (pairingKeys[pairingKeyOff] != 1) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        } else {
            pairingKeyOff++;
        }

        crypto.ecdh.init(scKeypair.getPrivate());
        short len;

        try {
            len = crypto.ecdh.generateSecret(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_LC], secret, (short) 0);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        if( SECURE_CHANNEL_DEBUG == true)
        	Util.arrayFillNonAtomic(apduBuffer, (short)0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE), (byte)0x08);
        else
        	crypto.random.generateData(apduBuffer, (short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
        
        crypto.sha512.update(secret, (short) 0, len);
        crypto.sha512.update(pairingKeys, pairingKeyOff, SC_SECRET_LENGTH);
        crypto.sha512.doFinal(apduBuffer, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);
        scEncKey.setKey(secret, (short) 0);
        scMacKey.setKey(secret, SC_SECRET_LENGTH);
        Util.arrayCopyNonAtomic(apduBuffer, SC_SECRET_LENGTH, secret, (short) 0, SC_BLOCK_SIZE);
        Util.arrayFillNonAtomic(secret, SC_BLOCK_SIZE, (short) (secret.length - SC_BLOCK_SIZE), (byte) 0);
        apdu.setOutgoingAndSend((short) 0, (short) (SC_SECRET_LENGTH + SC_BLOCK_SIZE));
    }

    /**
     * Processes the MUTUALLY AUTHENTICATE command.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    public void mutuallyAuthenticate(APDU apdu) {
        if (!scEncKey.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        boolean oldMutuallyAuthenticated = mutuallyAuthenticated;
        mutuallyAuthenticated = true;

        byte[] apduBuffer = apdu.getBuffer();
        short len = preprocessAPDU(apduBuffer);

        if (oldMutuallyAuthenticated) {
            ISOException.throwIt(ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED);
        }

        if (len != SC_SECRET_LENGTH) {
            reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        crypto.random.generateData(apduBuffer, SC_OUT_OFFSET, SC_SECRET_LENGTH);
        respond(apdu, len, ISO7816.SW_NO_ERROR);
    }

    /**
     * Processes the LOAD_CERTS command. Copies the APDU buffer into `certs`.
     * This function expects a DER signature and may only be called once.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    public void loadCert(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        if (!certEmpty) {
            // Card cert may only be set once and never overwritten
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Save the certificate
        if (apduBuffer[ISO7816.OFFSET_LC] <= (byte) CERTIFICATE_MAX_LEN) {
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, idCertificate, (short) 0, (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xff));
            certEmpty = false;
        } else {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * Load certificate for sender
     *
     * @param IncomingCert
     * @param IncomingCertLen
     */
    public void SenderloadCert(byte[] IncomingCert, short IncomingCertLen) {
        if (CardidCertStatus != ID_CERTIFICATE_EMPTY) {
            // Card cert may only be set once and never overwritten
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        // Save the certificate
        if (SenderidCertificate == null) {
            SenderidCertificate = JCSystem.makeTransientByteArray(CERTIFICATE_MAX_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        }

        if (IncomingCertLen > CERTIFICATE_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        } else {
            Util.arrayCopyNonAtomic(IncomingCert, (short) 0, SenderidCertificate, (short) 0, IncomingCertLen);
            CardidCertStatus = ID_CERTIFICATE_LOCKED;
            CardidCertLen = IncomingCertLen;
        }
    }

    /**
     * Set salt for sender card
     *
     * @param salt
     */
    void SetSenderSalt(byte[] salt) {
        Util.arrayCopyNonAtomic(salt, (short) 0, SenderSalt, (short) 0, (short) 32);
    }

    /**
     * Retrieve salt for sender card
     *
     * @return
     */
    public byte[] GetSenderSalt() {
        return SenderSalt;
    }

    /**
     * Processes the IDENTIFY_CARD command. Returns the card public key, and a signature on the
     * challenge salt, to prove ownership of the key.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    public void identifyCard(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        // Ensure the received challenge is appropriate length
        if (apduBuffer[ISO7816.OFFSET_LC] != MessageDigest.LENGTH_SHA_256) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short responseStart = (short) ISO7816.OFFSET_CDATA + (short) MessageDigest.LENGTH_SHA_256;
        short off = responseStart;

        // Copy card ID pubKey to the response buffer
        ECPublicKey pk = (ECPublicKey) idKeypair.getPublic();
        short pubkeyLen = pk.getW(apduBuffer, (short) (off + 2)); // Copy pubkey after TLV type and len
        apduBuffer[off++] = (byte) 0x80; // TLV pubkey type
        apduBuffer[off++] = (byte) pubkeyLen; // TLV pubkey len
        off += pubkeyLen;

        // Sign the challenge and copy signature to response buffer
        eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
        short sigLen = eccSig.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, apduBuffer, off);
        off += sigLen;

        // Send the response
        apdu.setOutgoingAndSend(responseStart, (short) (off - responseStart));
    }
    
    public ECPublicKey GetCardPublicKey()
    {
    	return (ECPublicKey)idKeypair.getPublic();
    }

    /**
     * Processes the PAIR command.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    public void pair(APDU apdu) {
        if (isOpen()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] apduBuffer = apdu.getBuffer();

        short len;

        if (apduBuffer[ISO7816.OFFSET_P1] == PAIR_P1_FIRST_STEP) {
            len = pairStep1(apduBuffer);
        } else if ((apduBuffer[ISO7816.OFFSET_P1] == PAIR_P1_LAST_STEP) && (preassignedPairingOffset != -1)) {
            len = pairStep2(apduBuffer);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Retrieve certificate for card
     *
     * @param ReturnBuffer buffer to place certificate into
     * @return length of certificate
     */
    public short GetCardCertificate(byte[] ReturnBuffer) {
        // Copy card certificate to response buffer
        short certLen = (short) (2 + (idCertificate[1] & 0xff));
        Util.arrayCopyNonAtomic(idCertificate, (short) 0, ReturnBuffer, (short) 0, certLen);
        return (certLen);
    }

    /**
     * Performs the first step of certificate based pairing. In this step, the card provides a CA signed certificate
     * of its card ID key, and proves ownership of this key with a signature on a challenge hash. The challenge hash
     * to be signed is computed as the sha256 hash of the client salt (provided by client) and card salt (generated randomly).
     * The card will also include its random salt in the response to the client, so that the client can reproduce the challenge
     * hash and verify the card signature.
     *
     * @param apduBuffer the APDU buffer
     * @return the length of the reply
     */
    private short pairStep1(byte[] apduBuffer) {
        // Validate command data length
        if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH + 2 + PUBKEY_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        // Make sure certificate exisits
        if (certEmpty) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
            return 0;
        }

        // Override first pairing slot
        preassignedPairingOffset = 0;

        // Compute ECDH secret
        final short pubKeyOff = (short) (ISO7816.OFFSET_CDATA + SC_SECRET_LENGTH);
        try {
            crypto.ecdh.init(idKeypair.getPrivate());
            crypto.ecdh.generateSecret(apduBuffer, (short) (pubKeyOff + 2), apduBuffer[pubKeyOff + 1], secret, (short) 0);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return 0;
        }

        // Hash client salt and ECDH secret and store in secret buffer
        // secretHash = sha256(clientSalt, ECDH secret)
        crypto.sha256.update(apduBuffer, ISO7816.OFFSET_CDATA, SC_SECRET_LENGTH);
        crypto.sha256.doFinal(secret, (short) 0, SC_SECRET_LENGTH, secret, (short) 0);

        // Response buffer offset (previous APDU buffer use was for temporary storage)
        short off = 0;

        // Generate random card salt, and copy to response buffer
        if (SecureChannel.SECURE_CHANNEL_DEBUG) {
            Util.arrayFillNonAtomic(apduBuffer, (short) off, SC_SECRET_LENGTH, (byte) 0x03);
        } else {
            crypto.random.generateData(apduBuffer, off, SC_SECRET_LENGTH);
        }
        off += SC_SECRET_LENGTH;

        // Copy card certificate to response buffer
        short certLen = (short) (2 + (idCertificate[1] & 0xff));
        Util.arrayCopyNonAtomic(idCertificate, (short) 0, apduBuffer, off, certLen);
        off += certLen;

        // Sign the secret hash, and copy the signature into the response buffer
        eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
        short sigLen = eccSig.signPreComputedHash(secret, (short) 0, SC_SECRET_LENGTH, apduBuffer, off);
        off += sigLen;

        // Compute the expected client cryptogram, by hashing the card salt and secret hash. Save
        // in second half of the secret buffer.
        // expectedCryptogram = sha256(cardSalt, secretHash)
        crypto.sha256.update(apduBuffer, (short) 0, SC_SECRET_LENGTH);
        crypto.sha256.doFinal(secret, (short) 0, SC_SECRET_LENGTH, secret, SC_SECRET_LENGTH);

        // Return total response length
        return off;
    }

    /**
     * Performs the last step of pairing. In this step the card verifies that the client has correctly solved its
     * challenge, authenticating it. It then proceeds to generate the pairing key and returns to the client the data
     * necessary to further establish a secure channel session.
     *
     * @param apduBuffer the APDU buffer
     * @return the length of the reply
     */
    private short pairStep2(byte[] apduBuffer) {
        // Validate command data length
        if (apduBuffer[ISO7816.OFFSET_LC] != SC_SECRET_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // At this point, the `secret` contains: [secretHash(32), cryptogram(32)]

        // Compare client cryptogram to the expected cryptogram (stored in secret buffer)
        if (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, secret, SC_SECRET_LENGTH, SC_SECRET_LENGTH) != 0) {
            preassignedPairingOffset = -1;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Generate random pairing salt & save pairing key. Copy pairing index and pairing salt into response buffer
        // pairingKey = sha256(pairingSalt, secretHash)
        if (SecureChannel.SECURE_CHANNEL_DEBUG) {
            Util.arrayFillNonAtomic(apduBuffer, (short) 1, SC_SECRET_LENGTH, (byte) 0x03);
        } else {
            crypto.random.generateData(apduBuffer, (short) 1, SC_SECRET_LENGTH);
        }
        crypto.sha256.update(apduBuffer, (short) 1, SC_SECRET_LENGTH);
        crypto.sha256.doFinal(secret, (short) 0, SC_SECRET_LENGTH, pairingKeys, (short) (preassignedPairingOffset + 1));
        pairingKeys[preassignedPairingOffset] = 1;
        remainingSlots--;
        apduBuffer[0] = (byte) (preassignedPairingOffset / PAIRING_KEY_LENGTH); // Pairing index

        preassignedPairingOffset = -1;

        return (1 + SC_SECRET_LENGTH);
    }


    /**
     * Verify salt and compute ECDH secret for pairing process
     *
     * @param Sendersalt
     * @param SendersaltLen
     * @param Receiversalt
     */
    public void CardSenderpair(byte[] Sendersalt, short SendersaltLen, byte[] Receiversalt) {

        // Make sure certificate exists
        if (certEmpty) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
            return;
        }

        // Compute ECDH secret
        short senderSaltLen;
        try {
            crypto.ecdh.init(idKeypair.getPrivate());
            byte permLen = SenderidCertificate[3];
            byte pubKeyLen = SenderidCertificate[5 + permLen];
            senderSaltLen = crypto.ecdh.generateSecret(SenderidCertificate, (short) (6 + permLen), pubKeyLen, CardSecret, (short) 0);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        crypto.sha512.update(Sendersalt, (short) 0, senderSaltLen);
        crypto.sha512.update(Receiversalt, (short) 0, (short) 32);
        crypto.sha512.doFinal(CardSecret, (short) 0, (short) 32, CardsessionKey, (short) 0);
        CardscEncKey.setKey(CardsessionKey, (short) 0);
        CardscMacKey.setKey(CardsessionKey, SC_SECRET_LENGTH);
    }

    /**
     * Sign a secret hash
     *
     * @param CardSig
     * @return signature
     */
    public short CardSignSession(byte[] CardSig) {
        // Compute the expected client cryptogram, by hashing the card session key and AESIV.
        // expectedCryptogram = sha256(CardsessionKey, CardAESIV)

        crypto.sha256.update(CardsessionKey, (short) 0, (short) (SC_SECRET_LENGTH * 2));
        crypto.sha256.doFinal(CardAESIV, (short) 0, (short) 16, CardHash, (short) 0);
        eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
        // Sign the secret hash, and copy the signature into the response buffer
        return eccSig.signPreComputedHash(CardHash, (short) 0, SC_SECRET_LENGTH, CardSig, (short) 0);
    }

    public short CardSignData( byte[] SigningData, short SigningDataLen, byte[] SignatureData, short SigOffset)
    {
        eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
        // Sign the secret hash, and copy the signature into the response buffer
     	return eccSig.sign(SigningData, (short)0, SigningDataLen, SignatureData, (short)SigOffset );	
    }
    
    /**
     * Check to see if the session has been properly set up.
     *
     * @param SenderSig sender card signature
     * @param SenderSigLen sender card signature length
     * @return if session can be verified
     */
    public boolean CardVerifySession(byte[] SenderSig, short SenderSigLen) {
        byte[] tempHash = new byte[100];
        Util.arrayCopyNonAtomic(CardsessionKey, (short) 0, tempHash, (short) 0, (short) (SC_SECRET_LENGTH * 2));
        Util.arrayCopyNonAtomic(CardAESIV, (short) 0, tempHash, (short) (SC_SECRET_LENGTH * 2), (short) 16);


        byte permLen = SenderidCertificate[3];
        byte pubKeyLen = SenderidCertificate[5 + permLen];
        byte[] SenderPublicKey = JCSystem.makeTransientByteArray(pubKeyLen, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        Util.arrayCopyNonAtomic(SenderidCertificate, (short) (6 + permLen), SenderPublicKey, (short) 0, pubKeyLen);

        KeyPair verifyidKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPrivate());
        localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPublic());
        verifyidKeypair.genKeyPair();
        ECPublicKey pub = (ECPublicKey) verifyidKeypair.getPublic();
        localsecp256k1.setCurveParameters(pub);
        pub.setW(SenderPublicKey, (short) (0), pubKeyLen);
        Signature eccSig2 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        eccSig2.init(pub, Signature.MODE_VERIFY);
        return eccSig2.verify(tempHash, (short) 0, (short) ((SC_SECRET_LENGTH * 2) + (short) 16), SenderSig, (short) 0, SenderSigLen);
    }

    /**
     * Verify signature of counterparty card
     *
     * @param RecieverSig receiver signature
     * @param RecieverSigLen length of receiver signature
     * @return if signature passed is legitimate
     */
    public boolean CardVerifySignature(byte[] RecieverSig, short RecieverSigLen) {
        byte[] temphash = new byte[100];
        Util.arrayCopyNonAtomic(CardsessionKey, (short) 0, temphash, (short) 0, (short) (SC_SECRET_LENGTH * 2));
        Util.arrayCopyNonAtomic(CardAESIV, (short) 0, temphash, (short) (SC_SECRET_LENGTH * 2), (short) 16);

        byte permLen = SenderidCertificate[3];
        byte pubKeyLen = SenderidCertificate[5 + permLen];

        KeyPair verifyidKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPrivate());
        localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPublic());
        verifyidKeypair.genKeyPair();
        ECPublicKey pub = (ECPublicKey) verifyidKeypair.getPublic();
        localsecp256k1.setCurveParameters(pub);
        pub.setW(SenderidCertificate, (short) (6 + permLen), pubKeyLen);

        eccSig.init(pub, Signature.MODE_VERIFY);
        return eccSig.verify(temphash, (short) 0, (short) ((SC_SECRET_LENGTH * 2) + (short) 16), RecieverSig, (short) 0, RecieverSigLen);
    }


    /**
     * Verify Sender certificate against signature from cert authority for card to card pairing
     *
     * @return if the certificate can be verified
     */
    public boolean CardVerifyCertificate() {
        byte permLen = SenderidCertificate[3];
        byte pubKeyLen = SenderidCertificate[5 + permLen];
        short pubSigLen = (short) (CardidCertLen - (short) (6 + permLen + pubKeyLen));
        byte[] CAPublicKey;
        if (USE_CA_DEMO_KEY) {
            CAPublicKey = SafecardDevCAPubKey;
        } else {
            CAPublicKey = SafecardProdCAPubKey;
        }

        KeyPair verifyidKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
        localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPrivate());
        localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPublic());
        verifyidKeypair.genKeyPair();
        ECPublicKey pub = (ECPublicKey) verifyidKeypair.getPublic();
        localsecp256k1.setCurveParameters(pub);
        pub.setW(CAPublicKey, (short) 0, (short) CAPublicKey.length);

        Signature eccSig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        eccSig.init(pub, Signature.MODE_VERIFY);
        short SignedDataLen = (short) (4 + permLen + pubKeyLen);
        return eccSig.verify(SenderidCertificate, (short) 2, SignedDataLen, SenderidCertificate, (short) (6 + permLen + pubKeyLen), pubSigLen);
    }


    /**
     * Getter for card-to-card pairing aesiv
     *
     * @return aesiv
     */
    public byte[] CardGetAESIV() {
        return CardAESIV;
    }

    /**
     * Processes the UNPAIR command. For security reasons the key is not only marked as free but also zero-ed out. This
     * method assumes that all security checks have been performed by the calling method.
     *
     * @param apduBuffer the APDU buffer
     */
    public void unpair(byte[] apduBuffer) {
        short off = checkPairingIndexAndGetOffset(apduBuffer[ISO7816.OFFSET_P1]);
        if (pairingKeys[off] == 1) {
            Util.arrayFillNonAtomic(pairingKeys, off, PAIRING_KEY_LENGTH, (byte) 0);
            remainingSlots++;
        }
    }

    /** Check to see if the certificate is empty or if it's been set
     *
     * @return if the certificate on this card is empty
     */
    public boolean CertEmpty() {
        return certEmpty;
    }

    /**
     * Decrypts the given APDU buffer. The plaintext is written in-place starting at the ISO7816.OFFSET_CDATA offset. The
     * MAC and padding are stripped. The LC byte is overwritten with the plaintext length. If the MAC cannot be verified
     * the secure channel is reset and the SW 0x6982 is thrown.
     *
     * @param apduBuffer the APDU buffer
     * @return the length of the decrypted
     */
    public short preprocessAPDU(byte[] apduBuffer) {
        if (!isOpen()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short apduLen = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);

        if (!verifyAESMAC(apduBuffer, apduLen)) {
            reset();
            ISOException.throwIt((short)((short)ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED +(short)1));
        }

        crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_DECRYPT, secret, (short) 0, SC_BLOCK_SIZE);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);
        short len = crypto.aesCbcIso9797m2.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA);

        apduBuffer[ISO7816.OFFSET_LC] = (byte) len;

        return len;
    }

    /**
     * Unencrypt message from paired card
     *
     * @param OutputData unencrypted data
     * @param len unencrypted data length
     */
    public void CardDecrypt(byte[] OutputData, short len) {
        //Copy out MAC from first 16 bytes
    	if( Card2CardStatus != CARD_TO_CARD_PAIRED)
    	{
    		ISOException.throwIt( (short)0x6987);
    		return;
    	}
        Util.arrayCopyNonAtomic(OutputData, (short) 0, CardAESCMAC, (short) 0, SC_BLOCK_SIZE);
        if (!VerifyCardAESCMAC(OutputData, SC_BLOCK_SIZE, (short) (len - (SC_BLOCK_SIZE)), CardAESCMAC)) {
            reset();
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        // //Probably cycle like this
        crypto.aesCbcIso9797m2.init(CardscEncKey, Cipher.MODE_DECRYPT, CardAESIV, (short) 0, SC_BLOCK_SIZE);
        crypto.aesCbcIso9797m2.doFinal(OutputData, SC_BLOCK_SIZE, (short) (len - (SC_BLOCK_SIZE)), OutputData, (short) 0);

        //Update the Init Vector
        Util.arrayCopyNonAtomic(CardAESCMAC, (short) 0, CardAESIV, (short) 0, SC_BLOCK_SIZE);

    }

    /**
     * Encrypt in place the data to be sent to the counterparty card
     *
     * @param OutputData unencrypted data to be encrypted to counterparty card
     * @param len length of unencrypted data
     * @return encrypted data length
     */
    public short CardEncrypt(byte[] OutputData, short len) {
    	if( Card2CardStatus != CARD_TO_CARD_PAIRED)
    	{
    		ISOException.throwIt( (short)0x6987);
    		return( 0 );
    	}
         crypto.aesCbcIso9797m2.init(CardscEncKey, Cipher.MODE_ENCRYPT, CardAESIV, (short) 0, SC_BLOCK_SIZE);
        len = crypto.aesCbcIso9797m2.doFinal(OutputData, (short) 0, len, OutputData, (short) 0);

        //Use the CardAESIV so it will cycle to the next MAC
        //TODO: Test this with multiple sequential APDU's over the same channel to ensure cycle is working correctly

        CalcCardAESMAC(OutputData, len, CardAESIV);

        //Prepend MAC
        //Shift the OutputData right 16 bytes to make room for MAC and then copy it into first 16 bytes
        Util.arrayCopyNonAtomic(OutputData, (short) 0, OutputData, SC_BLOCK_SIZE, len);
        Util.arrayCopyNonAtomic(CardAESIV, (short) 0, OutputData, (short) 0, SC_BLOCK_SIZE);
        len += SC_BLOCK_SIZE;

        return len;
    }


    /**
     * Verifies the AES CBC-MAC, either natively or with a software implementation. Can only be called from the
     * preprocessAPDU method since it expects the input buffer to be formatted in a particular way.
     *
     * @param apduBuffer the APDU buffer
     * @param apduLen    the data len
     */
    private boolean verifyAESMAC(byte[] apduBuffer, short apduLen) {
        scMac.init(scMacKey, Signature.MODE_VERIFY);
        scMac.update(apduBuffer, (short) 0, ISO7816.OFFSET_CDATA);
        scMac.update(secret, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - ISO7816.OFFSET_CDATA));

        return scMac.verify(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA, SC_BLOCK_SIZE);
    }

    /**
     * Sends the response to the command. This the given SW is appended to the data automatically. The response data must
     * be placed starting at the SecureChannel.SC_OUT_OFFSET offset, to leave place for the SecureChannel-specific data at
     * the beginning of the APDU.
     *
     * @param apdu the APDU object
     * @param len  the length of the plaintext
     */
    public void respond(APDU apdu, short len, short sw) {
        byte[] apduBuffer = apdu.getBuffer();

        Util.setShort(apduBuffer, (short) (SC_OUT_OFFSET + len), sw);
        len += 2;

        crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_ENCRYPT, secret, (short) 0, SC_BLOCK_SIZE);
        //37                              // 21
        len = crypto.aesCbcIso9797m2.doFinal(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));

        apduBuffer[0] = (byte) (len + SC_BLOCK_SIZE);

        //Calculates MAC and places it in first 16 bytes of apduBuffer
        computeAESMAC(len, apduBuffer);

        //Copies the newly calculated MAC into "secret" for usage in the next cipher cycle
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);

        len += SC_BLOCK_SIZE;
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
    }

    /**
     * Respond over encrypted channel
     *
     * @param apdu Javacard APDU buffer
     * @param OutgoingData Data to be sent
     * @param len Length of data to be sent
     * @param sw SW value of sent data
     */
    public void respond(APDU apdu, byte[] OutgoingData, short len, short sw) {
        byte[] apduBuffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(OutgoingData, (short) 0, apduBuffer, SC_OUT_OFFSET, len);
        respond(apdu, len, sw);
    }

    /**
     * Computes the AES CBC-MAC, either natively or with a software implementation. Can only be called from the respond
     * method since it expects the input buffer to be formatted in a particular way.
     *
     * @param len        the data len
     * @param apduBuffer the APDU buffer
     */
    private void computeAESMAC(short len, byte[] apduBuffer) {
        scMac.init(scMacKey, Signature.MODE_SIGN);
        scMac.update(apduBuffer, (short) 0, (short) 1);
        scMac.update(secret, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - 1));
        scMac.sign(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), len, apduBuffer, ISO7816.OFFSET_CDATA);
    }

    /**
     * Calculates the MAC for card to card secure channel messages
     *
     * @param Data        The ciphertext
     * @param len         The length of the ciphertext
     * @param CardAESCMAC The output buffer for the returned MAC
     */
    public void CalcCardAESMAC(byte[] Data, short len, byte[] CardAESCMAC) {
        //Prepend 16 bytes
        scMac.init(CardscMacKey, Signature.MODE_SIGN);
        byte[] meta = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        scMac.update(meta, (short) 0, (short) 16);
        scMac.sign(Data, (short) 0, len, CardAESCMAC, (short) 0);
    }

    /**
     * Verify AES MAC was properly set
     *
     * @param Data Data to be verified against
     * @param offset offset into buffer of data
     * @param len length of data
     * @param CardAESMAC AES MAC
     * @return if mac was properly verified
     */
    public boolean VerifyCardAESCMAC(byte[] Data, short offset, short len, byte[] CardAESMAC) {
        scMac.init(CardscMacKey, Signature.MODE_VERIFY);
        byte[] meta = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        scMac.update(meta, (short) 0, (short) 16);
        return scMac.verify(Data, offset, len, CardAESMAC, (short) 0, (short) 16);
    }

    /**
     * Copies the public key used for EC-DH in the given buffer.
     *
     * @param buf the buffer
     * @param off the offset in the buffer
     * @return the length of the public key
     */
    public short copyPublicKey(byte[] buf, short off) {
        ECPublicKey pk = (ECPublicKey) scKeypair.getPublic();
        return pk.getW(buf, off);
    }

    /**
     * Returns whether a secure channel is currently established or not.
     *
     * @return whether a secure channel is currently established or not.
     */
    public boolean isOpen() {
        return scEncKey.isInitialized() && scMacKey.isInitialized() && mutuallyAuthenticated;
    }

    /**
     * Returns the number of still available pairing slots.
     */
    public byte getRemainingPairingSlots() {
        return remainingSlots;
    }

    /**
     * Called before sending the public key to the client, gives a chance to change keys if needed.
     */
    public void updateSecureChannelCounter() {
        if (scCounter < SC_COUNTER_MAX) {
            scCounter++;
        } else {
            if( SECURE_CHANNEL_DEBUG == true)
            {
                ECPrivateKey idPrivateKey = (ECPrivateKey) scKeypair.getPrivate();
                idPrivateKey.setS(DebugMasterPrivateKey, (short) 0, (short) 32);
                byte[] PublicKeystr = new byte[70];
                short PublicKeyLength = localsecp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short) 0);
                ECPublicKey PublicKey = (ECPublicKey) scKeypair.getPublic();
                PublicKey.setW(PublicKeystr, (short) 0, PublicKeyLength);
            }
            else
            	scKeypair.genKeyPair();
            scCounter = 0;
        }
    }

    /**
     * Resets the Secure Channel, invalidating the current session. If no session is opened, this does nothing.
     */
    public void reset() {
        scEncKey.clearKey();
        scMacKey.clearKey();
        mutuallyAuthenticated = false;
        CardidCertStatus = ID_CERTIFICATE_EMPTY;
    }

    /**
     * Updates the pairing secret. Does not affect existing pairings.
     *
     * @param aPairingSecret the buffer
     * @param off            the offset
     */
    public void updatePairingSecret(byte[] aPairingSecret, byte off) {
        Util.arrayCopy(aPairingSecret, off, pairingSecret, (short) 0, SC_SECRET_LENGTH);
    }

    /**
     * Returns the offset in the pairingKey byte array of the pairing key with the given index. Throws 0x6A86 if the index
     * is invalid
     *
     * @param idx the index
     * @return the offset
     */
    private short checkPairingIndexAndGetOffset(byte idx) {
        short off = (short) (idx * PAIRING_KEY_LENGTH);

        if (off >= ((short) pairingKeys.length)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        return off;
    }

    /**
     * set Card ID Certificate status
     *
     * @param value Cert status
     */
    public void SetCardidCertStatus(byte value) {
        CardidCertStatus = value;
    }
}

