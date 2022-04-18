package io.gridplus.phonon;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * @author MikeZercher
 * @author Dan Veenstra
 * @author Nate Maile
 * GridPlus https://gridplus.io
 */

public class PhononApplet extends Applet {    //implements ExtendedLength {
    public static final short PHONON_KEY_LENGTH = 256;
    public static final short MAX_NUMBER_PHONONS = 256;
    public static final short MAX_EXTENDED_SCHEMA_BUFFER = 100;
    // runtime configs
    static final short APPLICATION_VERSION = (short) 0x0004;
    // constants
    static final byte UNINITIALIZED_BYTE = (byte) 0xff;
    static final short UNINITIALIZED_SHORT = (short) 0xffff;
    static final byte PHONON_STATUS_INITIALIZED = (byte) 0x01;
    static final byte PHONON_STATUS_DELETED = (byte) 0x04;
    static final byte CAPABILITY_SECURE_CHANNEL = (byte) 0x01;
    static final byte CAPABILITY_KEY_MANAGEMENT = (byte) 0x02;
    static final byte CAPABILITY_CREDENTIALS_MANAGEMENT = (byte) 0x04;
    //	  static final byte APPLICATION_CAPABILITIES = (byte)(CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT | CAPABILITY_NDEF);
    static final byte APPLICATION_CAPABILITIES = (byte) (CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT);
    // apdu instructions
    static final byte INS_INIT = (byte) 0xFE;
    static final byte INS_MINE_PHONON = (byte)0x41;
    static final byte INS_CREATE_PHONON = (byte) 0x30;
    static final byte INS_SET_PHONON_DESCRIPTOR = (byte) 0x31;
    static final byte INS_LIST_PHONONS = (byte) 0x32;
    static final byte INS_GET_PHONON_PUB_KEY = (byte) 0x33;
    static final byte INS_DESTROY_PHONON = (byte) 0x34;
    static final byte INS_SEND_PHONONS = (byte) 0x35;
    static final byte INS_RECV_PHONONS = (byte) 0x36;
    static final byte INS_SET_RECV_LIST = (byte) 0x37;
    static final byte INS_TRANSACTION_ACK = (byte) 0x38;
    static final byte INS_INIT_CARD_PAIRING = (byte) 0x50;
    static final byte INS_CARD_SENDER_PAIR = (byte) 0x51;
    static final byte INS_CARD_RECEIVER_PAIR = (byte) 0x52;
    static final byte INS_CARD_FINALIZE = (byte) 0x53;
    static final byte INS_VERIFY_PIN = (byte) 0x20;
    static final byte INS_CHANGE_PIN = (byte) 0x21;
    static final byte INS_CHG_FRIENDLY_NAME = (byte) 0x56;
    static final byte INS_GET_FRIENDLY_NAME = (byte) 0x57;
    static final byte INS_GET_AVAILABLE_MEMORY = (byte) 0x99;
    static final byte PIN_LENGTH = 6;
    static final byte PIN_MAX_RETRIES = 10;  	//change to 10
    static final byte PAIRING_MAX_CLIENT_COUNT = 1;
    static final byte UID_LENGTH = 16;
    static final short CHAIN_CODE_SIZE = 32;
    // tlv values
    static final byte TLV_PUB_KEY = (byte) 0x80;
    static final byte TLV_PRIV_KEY = (byte) 0x81;
    static final byte TLV_PHONON_KEY = (byte) 0x40;
    static final byte TLV_PHONON_INDEX = (byte) 0x41;
    static final byte TLV_PAIRING_SLOT = (byte) 0x03;
    static final byte TLV_INT = (byte) 0x02;
    static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;
    static final byte TLV_UID = (byte) 0x8F;
    static final byte TLV_CAPABILITIES = (byte) 0x8D;
    static final byte CHANGE_PIN_P1_USER_PIN = 0x00;
    static final byte CHANGE_PIN_P1_PAIRING_SECRET = 0x02;
    static final byte TLV_SET_PHONON_DESCRIPTOR = (byte) 0x50;
    static final byte TLV_PHONON_COLLECTION = (byte) 0x52;
    static final byte TLV_PHONON_PRIVATE_DESCRIPTOR = (byte) 0x44;
    static final byte TLV_PHONON_INDEX_COUNT = (byte) 0x42;
    static final byte TLV_PHONON_TRANSFER_PACKET = (byte) 0x43;
    static final byte TLV_PHONON_FILTER = (byte) 0x60;
    static final byte TLV_SET_PHONON_KEY_INDEX = (byte) 0x41;
    static final byte TLV_PHONON_PUB_KEY_LIST = (byte) 0x7f;
    static final byte TLV_SET_PHONON_CURRENCY = (byte) 0x82;
    static final byte TLV_SET_PHONON_VALUE = (byte) 0x83;
    static final byte TLV_PHONON_LESS_THAN = (byte) 0x84;
    static final byte TLV_PHONON_GREATER_THAN = (byte) 0x85;
    static final byte LIST_FILTER_ALL = (byte) 0x00;
    static final byte LIST_FILTER_LESS_THAN = (byte) 0x01;
    static final byte LIST_FILTER_GREATER_THAN = (byte) 0x02;
    static final byte LIST_FILTER_GT_AND_LT = (byte) 0x03;
    static final byte LIST_FILTER_LAST = (byte) 0x03;
    static final byte TLV_CARD_CERTIFICATE = (byte) 0x90;
    static final byte TLV_SALT = (byte) 0x91;
    static final byte TLV_AESIV = (byte) 0x92;
    static final byte TLV_RECEIVER_SIG = (byte) 0x93;
    static final byte KEY_CURVE_TYPE_SECP256K1 = (byte) 0x00;
    static final byte KEY_CURVE_TYPE_NATIVE = (byte) 0x01;
    static final byte KEY_CURVE_TYPE_MAX = KEY_CURVE_TYPE_NATIVE;
    static final byte TLV_SCHEMA_VERSION = (byte) 0x88;
    static final byte TLV_EXTENDED_SCHEMA_VERSION = (byte) 0x89;
    static final byte TLV_VALUE_BASE = (byte) 0x83;
    static final byte TLV_VALUE_EXPONENT = (byte) 0x86;
    static final byte TLV_KEY_CURVE_TYPE = (byte) 0x87;
    static final short KEY_CURRENCY_TYPE_UNDEFINED = 0x0000;
    static final short KEY_CURRENCY_TYPE_BITCOIN = 0x0001;
    static final short KEY_CURRENCY_TYPE_ETHEREUM = 0x0002;
    static final short KEY_CURRENCY_TYPE_NATIVE = 0x0003;
    static final short KEY_CURRENCY_TYPE_MAX = (short)0x7fff;
    static final byte  TLV_EXTENDED_NATIVE_SIGNATURE = (byte) 0x94;


    private static final boolean DEBUG_MODE = false;
    // runtime variables
    private byte[] friendlyName;
    private Crypto crypto;
    private SECP256k1 secp256k1;
    private SecureChannel secureChannel;
    private byte[] uid;
    private ECPublicKey publicKey;
    private ECPrivateKey privateKey;

    // re-usable buffers/runtime objects
    private byte[] ScratchBuffer;
    private byte[] TransBuffer;
    private Bertlv globalBertlv;
    private short[] AvailableMemory;
    private short[] PhononList;
    private short[] SendPhononList;
    private short[] DeletedPhononList;
    private Phonon[] PhononArray;

    byte[] TempExtendedSchema;
    KeyPair PhononKey;
    private OwnerPIN pin;
    private short phononKeyIndex = 0;
    private short DeletedPhononIndex = 0;
    private short PhononListCount;
    private short PhononListLastSent;
    private short SendPhononListCount;
    private short SendPhononListLastSent;
    private boolean DebugKeySet;
    private short friendlyNameLen=0;
    private short MiningRarity;

    public PhononApplet() {
    	crypto = new Crypto();
      	secp256k1 = new SECP256k1(crypto);
        secureChannel = new SecureChannel(PAIRING_MAX_CLIENT_COUNT, crypto, secp256k1);

        uid = new byte[UID_LENGTH];
        try {
        	crypto.random.generateData(uid, (short) 0, UID_LENGTH);
        } catch (Exception e) {
        	ISOException.throwIt((short)0x6f01);
        }

        PhononArray = new Phonon[MAX_NUMBER_PHONONS];
        PhononList = new short[MAX_NUMBER_PHONONS];
        SendPhononList = new short[MAX_NUMBER_PHONONS];
        DeletedPhononList = new short[MAX_NUMBER_PHONONS];
        PhononListCount = 0;
        PhononListLastSent = 0;
        SendPhononListCount = 0;
        SendPhononListLastSent = 0;
        friendlyNameLen = 0;
        secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_NOT_INITIALIZED;


        ScratchBuffer = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_DESELECT);
        TransBuffer = JCSystem.makeTransientByteArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
        TempExtendedSchema = JCSystem.makeTransientByteArray(MAX_EXTENDED_SCHEMA_BUFFER, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);

        publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
        resetCurveParameters();
        PhononKey = new KeyPair(KeyPair.ALG_EC_FP, PHONON_KEY_LENGTH);

        globalBertlv = new Bertlv();

        friendlyName = new byte[40];
       	AvailableMemory = JCSystem.makeTransientShortArray((short) 6, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    }

    /**
     * Install the phonon applet to the card
     *
     * @param bArray
     * @param bOffset
     * @param bLength
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new io.gridplus.phonon.PhononApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }


    /**
     * Process incoming apdu and dispatch to proper function
     *
     * @param apdu the JCRE-owned APDU object.
     * @throws ISOException
     */
    public void process(APDU apdu) throws ISOException {
        // Good practice: Return 9000 on SELECT
        byte[] buf = apdu.getBuffer();
        if (SecureChannel.SECURE_CHANNEL_DEBUG && !DebugKeySet) {
            secureChannel.SetDebugKey();
            DebugKeySet = true;
        }

        if (DEBUG_MODE) {
            if ((buf[ISO7816.OFFSET_INS] != INS_CREATE_PHONON)
                    && (buf[ISO7816.OFFSET_INS] != INS_LIST_PHONONS)
                    && (buf[ISO7816.OFFSET_INS] != INS_DESTROY_PHONON)
                    && (buf[ISO7816.OFFSET_INS] != INS_GET_PHONON_PUB_KEY)
                    && (buf[ISO7816.OFFSET_INS] != INS_SEND_PHONONS)
                    && (buf[ISO7816.OFFSET_INS] != INS_RECV_PHONONS)
                    && (buf[ISO7816.OFFSET_INS] != INS_SET_RECV_LIST)
                    && (buf[ISO7816.OFFSET_INS] != INS_TRANSACTION_ACK)
                    && (buf[ISO7816.OFFSET_INS] != INS_INIT_CARD_PAIRING)
                    && (buf[ISO7816.OFFSET_INS] != INS_CARD_SENDER_PAIR)
                    && (buf[ISO7816.OFFSET_INS] != INS_CARD_RECEIVER_PAIR)
                    && (buf[ISO7816.OFFSET_INS] != INS_CARD_FINALIZE)
                    && (buf[ISO7816.OFFSET_INS] != INS_SET_PHONON_DESCRIPTOR)
                    && (buf[ISO7816.OFFSET_INS] != INS_GET_AVAILABLE_MEMORY)
            ) {
                if (buf[ISO7816.OFFSET_INS] != SecureChannel.INS_IDENTIFY_CARD &&
                        buf[ISO7816.OFFSET_INS] != SecureChannel.INS_LOAD_CERT) {
                    if (pin == null) {
                        processInit(apdu);
                        return;
                    }

                }
                if (selectingApplet()) {
                    selectApplet(apdu);
                    return;
                }
            }
        } else {
            if (buf[ISO7816.OFFSET_INS] != SecureChannel.INS_IDENTIFY_CARD &&
                    buf[ISO7816.OFFSET_INS] != SecureChannel.INS_LOAD_CERT &&
                    buf[ISO7816.OFFSET_INS] != INS_GET_AVAILABLE_MEMORY) {
                if (pin == null) {
                    processInit(apdu);
                    return;
                }

            }
            if (selectingApplet()) {
                selectApplet(apdu);
                return;
            }
        }
        try {

            switch (buf[ISO7816.OFFSET_INS]) {
                case SecureChannel.INS_IDENTIFY_CARD: {
                    secureChannel.identifyCard(apdu);
                    break;
                }
                case SecureChannel.INS_LOAD_CERT: {
                    secureChannel.loadCert(apdu);
                    break;
                }
                case SecureChannel.INS_OPEN_SECURE_CHANNEL: {
                    secureChannel.openSecureChannel(apdu);
                    secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_NOT_INITIALIZED;
                    break;
                }
                case SecureChannel.INS_MUTUALLY_AUTHENTICATE: {
                    secureChannel.mutuallyAuthenticate(apdu);
                    break;
                }
                case SecureChannel.INS_PAIR: {
                    secureChannel.pair(apdu);
                    break;
                }
                case SecureChannel.INS_UNPAIR: {
                    unpair(apdu);
                    secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_NOT_INITIALIZED;
                    break;
                }
                case INS_VERIFY_PIN: {
                    verifyPIN(apdu);
                    break;
                }
                case INS_CHANGE_PIN: {
                    changePIN(apdu);
                    break;
                }
                case INS_CREATE_PHONON: {
                    createPhonon(apdu);
                    break;
                }
                case INS_SET_PHONON_DESCRIPTOR: {
                    SetPhononDescriptor(apdu);
                    break;
                }
                case INS_LIST_PHONONS: {
                    ListPhonons(apdu);
                    break;
                }

                case INS_GET_PHONON_PUB_KEY: {
                    GetPhononPublicKey(apdu);
                    break;
                }

                case INS_DESTROY_PHONON: {
                    DestroyPhonon(apdu);
                    break;
                }

                case INS_SEND_PHONONS: {
                    SendPhonons(apdu);
                    break;
                }

                case INS_RECV_PHONONS: {
                    ReceivePhonons(apdu);
                    break;
                }

                case INS_SET_RECV_LIST: {
                    SetReceivePhononList(apdu);
                    break;
                }

                case INS_INIT_CARD_PAIRING: {
                    InitCardPairing(apdu);
                    break;
                }

                case INS_CARD_SENDER_PAIR: {
                    SenderPairing(apdu);
                    break;
                }

                case INS_CARD_RECEIVER_PAIR: {
                    ReceiverPairing(apdu);
                    break;
                }

                case INS_CARD_FINALIZE: {
                    FinalizeCardPairing(apdu);
                    break;
                }

                case INS_CHG_FRIENDLY_NAME: {
                    ChangeFriendlyName(apdu);
                    break;
                }
                case INS_GET_FRIENDLY_NAME: {
                    GetFriendlyName(apdu);
                    break;
                }

                case INS_MINE_PHONON:
                {
                	MinePhonon( apdu);
                	break;
                }

                case INS_GET_AVAILABLE_MEMORY: {
                    byte[] apduBuffer = apdu.getBuffer();
                    if (!DEBUG_MODE) {
                        if (secureChannel.isOpen()) {
                            secureChannel.preprocessAPDU(apduBuffer);
                        }
                    }
                    JCSystem.getAvailableMemory(AvailableMemory, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
                    JCSystem.getAvailableMemory(AvailableMemory, (short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
                    JCSystem.getAvailableMemory(AvailableMemory, (short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
                    Util.setShort(apduBuffer, (short) 0, AvailableMemory[0]);
                    Util.setShort(apduBuffer, (short) 2, AvailableMemory[1]);
                    Util.setShort(apduBuffer, (short) 4, AvailableMemory[2]);
                    Util.setShort(apduBuffer, (short) 6, AvailableMemory[3]);
                    Util.setShort(apduBuffer, (short) 8, AvailableMemory[4]);
                    Util.setShort(apduBuffer, (short) 10, AvailableMemory[5]);

                    if (secureChannel.isOpen()) {
                        secureChannel.respond(apdu, apduBuffer, (short) 12, ISO7816.SW_NO_ERROR);
                    } else {
                        apdu.setOutgoingAndSend((short) 0, (short) 12);
                    }

                    break;
                }

                default:
                    // good practice: If you don't know the INStruction, say so:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException sw) {
            handleException(apdu, sw.getReason());
        } catch (CryptoException ce) {
            handleException(apdu, (short) (0x6c00 | ce.getReason()));
        } catch (Exception e) {
            handleException(apdu, (ISO7816.SW_UNKNOWN));
        }

        if (shouldRespond(apdu)) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
        }
        JCSystem.requestObjectDeletion();
    }

    /**
     * Helper function for returning error codes when an exception is thrown.
     *
     * @param apdu the JCRE-owned APDU object.
     * @param sw   javacard response error code value
     */
    private void handleException(APDU apdu, short sw) {
        if (shouldRespond(apdu) && (sw != ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED)) {
            secureChannel.respond(apdu, (short) 0, sw);
        } else {
            ISOException.throwIt(sw);
        }
    }

    /**
     * Check to see if a response on the secure channel is warranted
     *
     * @param apdu the JCRE-owned APDU object.
     * @return
     */
    private boolean shouldRespond(APDU apdu) {
        return secureChannel.isOpen() && (apdu.getCurrentState() != APDU.STATE_FULL_OUTGOING);
    }

    /**
     * Initiate a card to card secure pairing.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void InitCardPairing(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_NOT_INITIALIZED;
        secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.isValidated()) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        byte[] IncomingData = apduBuffer;

        short ptr = ISO7816.OFFSET_CDATA;

        if (IncomingData[ptr] != TLV_CARD_CERTIFICATE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        ptr++;
        short CertLen = (short) ((short) IncomingData[ptr] & (short) 0x00FF);
        ptr++;
        Util.arrayCopyNonAtomic(IncomingData, ptr, ScratchBuffer, (short) 0, CertLen);

        secureChannel.SetCardidCertStatus((byte) 0x00);
        secureChannel.SenderloadCert(ScratchBuffer, CertLen);
        boolean verifyStatus = secureChannel.CardVerifyCertificate();

        if (!verifyStatus) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        if (secureChannel.CertEmpty()) {
            // Card cert was not initialized
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        short Offset = 0;
        apduBuffer = apdu.getBuffer();

        short CardCertLen = secureChannel.GetCardCertificate(ScratchBuffer);
        Bertlv berCert = globalBertlv;
        berCert.BuildTLVStructure(TLV_CARD_CERTIFICATE, CardCertLen, ScratchBuffer, apduBuffer, Offset);
        Offset += berCert.BuildLength;

        byte[] salt = new byte[32];

        if (SecureChannel.SECURE_CHANNEL_DEBUG) {
            Util.arrayFillNonAtomic(salt, (short) 0, (short) 32, (byte) 0x01);
        } else {
            crypto.random.generateData(salt, (short) 0, (short) 32);
        }

        secureChannel.SetSenderSalt(salt);

        Bertlv berCardSalt = globalBertlv;
        berCardSalt.BuildTLVStructure(TLV_SALT, (short) 32, salt, apduBuffer, Offset);
        Offset += berCardSalt.BuildLength;
        secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_INIT_CARD_PAIR;

        if (DEBUG_MODE) {
            apdu.setOutgoingAndSend((short) 0, Offset);
        } else {
            secureChannel.respond(apdu, apduBuffer, Offset, ISO7816.SW_NO_ERROR);
        }
    }

    /**
     * Exchange the pairing initation data from INIT_CARD_PAIRING with the card to be paired.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void SenderPairing(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.isValidated()) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        byte[] IncomingData = apduBuffer;

        short ptr = ISO7816.OFFSET_CDATA;

        if (IncomingData[ptr] != TLV_CARD_CERTIFICATE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        ptr++;
        short CertLen = (short) ((short) IncomingData[ptr] & (short) 0x00FF);
        ptr++;
        Util.arrayCopyNonAtomic(IncomingData, ptr, ScratchBuffer, (short) 0, CertLen);

        secureChannel.SetCardidCertStatus((byte) 0x00);
        secureChannel.SenderloadCert(ScratchBuffer, CertLen);

        boolean verifyStatus = secureChannel.CardVerifyCertificate();

        if (!verifyStatus) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }
        ptr += CertLen;

        if (IncomingData[ptr] != TLV_SALT) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        ptr++;
        short SenderSaltLen = IncomingData[ptr];
        ptr++;
        byte[] SenderSalt = TransBuffer;
        Util.arrayCopyNonAtomic(IncomingData, ptr, SenderSalt, (short) 0, SenderSaltLen);

        byte[] ReceiverSalt = new byte[32];

        if (SecureChannel.SECURE_CHANNEL_DEBUG) {
            Util.arrayFillNonAtomic(ReceiverSalt, (short) 0, (short) 32, (byte) 0x02);
        } else {
            crypto.random.generateData(ReceiverSalt, (short) 0, (short) 32);
        }

        short Offset = 0;

        if (SecureChannel.SECURE_CHANNEL_DEBUG) {
            Util.arrayFillNonAtomic(secureChannel.CardAESIV, (short) 0, (short) 16, (byte) 0x03);
        } else {
            crypto.random.generateData(secureChannel.CardAESIV, (short) 0, (short) 16);
        }

        secureChannel.CardSenderpair(SenderSalt, SenderSaltLen, ReceiverSalt);

        apduBuffer = apdu.getBuffer();
        Bertlv berCardSalt = globalBertlv;
        berCardSalt.BuildTLVStructure(TLV_SALT, (short) 32, ReceiverSalt, apduBuffer, (short) 0);
        Offset += berCardSalt.BuildLength;

        Bertlv berCardAES = globalBertlv;
        berCardAES.BuildTLVStructure(TLV_AESIV, (short) 16, secureChannel.CardGetAESIV(), apduBuffer, Offset);
        Offset += berCardAES.BuildLength;

        Util.arrayFillNonAtomic(ScratchBuffer, (short) 0, (short) ScratchBuffer.length, (byte) 0x00);
        short sigLen = secureChannel.CardSignSession(ScratchBuffer);
        Bertlv berCardSig = globalBertlv;
        berCardSig.BuildTLVStructure(TLV_RECEIVER_SIG, sigLen, ScratchBuffer, apduBuffer, Offset);
        Offset += berCardSig.BuildLength;
        secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_PAIR_1;

        if (DEBUG_MODE) {
            apdu.setOutgoingAndSend((short) 0, Offset);
        } else {
            secureChannel.respond(apdu, apduBuffer, Offset, ISO7816.SW_NO_ERROR);
        }

    }

    /**
     * Exchange the returned pairing data from CARD_PAIR with the initiating card.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void ReceiverPairing(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);
            if (!pin.isValidated()) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }
        if( secureChannel.Card2CardStatus != secureChannel.CARD_TO_CARD_INIT_CARD_PAIR )
        {
        	secureChannel.respond( apdu,  (short)0, (short)0x6987);
        	return;
        }

        Bertlv ReceiveSaltTLV = globalBertlv;
        byte[] IncomingData = ScratchBuffer;

        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short) 0, len);
        ReceiveSaltTLV.LoadTag(IncomingData);

        if (ReceiveSaltTLV.GetTag() != TLV_SALT) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        byte[] ReceiverSalt = TransBuffer;

        Util.arrayCopyNonAtomic(ReceiveSaltTLV.GetData(), (short) 0, ReceiverSalt, (short) 0, ReceiveSaltTLV.GetLength());

        Bertlv ReceiveAESTLV = globalBertlv;
        short Offset = (short) (ReceiveSaltTLV.GetLength() + 2);
        ReceiveAESTLV.LoadTagBase(IncomingData, Offset);

        if (ReceiveAESTLV.GetTag() != TLV_AESIV || ReceiveAESTLV.GetLength() != 16) {
            ISOException.throwIt((short) (ISO7816.SW_WRONG_DATA + 1));
            return;
        }

        Util.arrayCopyNonAtomic(ReceiveAESTLV.GetData(), (short) 0, secureChannel.CardAESIV, (short) 0, ReceiveAESTLV.GetLength());

        Offset += (short) (ReceiveAESTLV.GetLength() + 2);
        Bertlv ReceiveSigTLV = globalBertlv;
        ReceiveSigTLV.LoadTagBase(IncomingData, Offset);

        if (ReceiveSigTLV.GetTag() != TLV_RECEIVER_SIG) {
            ISOException.throwIt((short) (ISO7816.SW_WRONG_DATA + 2));
            return;
        }
        secureChannel.CardSenderpair(secureChannel.GetSenderSalt(), ReceiveSaltTLV.GetLength(), ReceiverSalt);
        boolean SigVerifyStatus = secureChannel.CardVerifySession(ReceiveSigTLV.GetData(), ReceiveSigTLV.GetLength());

        if (!SigVerifyStatus) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        Offset = 0;
        Util.arrayFillNonAtomic(ScratchBuffer, (short) 0, (short) ScratchBuffer.length, (byte) 0x00);

        short sigLen = secureChannel.CardSignSession(ScratchBuffer);

        Bertlv berCardSig = globalBertlv;
        berCardSig.BuildTLVStructure(TLV_RECEIVER_SIG, sigLen, ScratchBuffer, apduBuffer);
        Offset += berCardSig.BuildLength;
        secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_PAIRED;


        if (DEBUG_MODE) {
            apdu.setOutgoingAndSend((short) 0, Offset);
        } else {
            secureChannel.respond(apdu, apduBuffer, Offset, ISO7816.SW_NO_ERROR);
        }

    }

    /**
     * Return the pairing info and initial card's signature on the session key to finalize the pairing.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void FinalizeCardPairing(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        secureChannel.preprocessAPDU(apduBuffer);
        if (!pin.isValidated()) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        if( secureChannel.Card2CardStatus != secureChannel.CARD_TO_CARD_PAIR_1)
        {
        	secureChannel.respond(apdu, (short)0, (short)0x6987);
        	return;
        }

        short ptr = ISO7816.OFFSET_CDATA;

        if (apduBuffer[ptr] != TLV_RECEIVER_SIG) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        ptr++;
        short SigLen = (short) ((short) apduBuffer[ptr] & (short) 0x00FF);
        ptr++;
        Util.arrayCopyNonAtomic(apduBuffer, ptr, ScratchBuffer, (short) 0, SigLen);

        boolean SigVerifyStatus = secureChannel.CardVerifySignature(ScratchBuffer, SigLen);
        if (!SigVerifyStatus) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        secureChannel.Card2CardStatus = secureChannel.CARD_TO_CARD_PAIRED;
    }

    /**
     * Create an empty phonon and return its public key. This phonon will be unspendable until a descriptor has been set.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void createPhonon(APDU apdu) {
        secp256k1.setCurveParameters((ECKey) PhononKey.getPrivate());
        secp256k1.setCurveParameters((ECKey) PhononKey.getPublic());

        byte[] apduBuffer1 = apdu.getBuffer();
        if( DEBUG_MODE == false)
        {
        	secureChannel.preprocessAPDU(apduBuffer1);

        	if (!pin.isValidated()) {
        		secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        		return;
        	}
        }


        byte KeyCurveType = apduBuffer1[ISO7816.OFFSET_P1];

        if (KeyCurveType > KEY_CURVE_TYPE_MAX) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        if (phononKeyIndex >= MAX_NUMBER_PHONONS && DeletedPhononIndex == 0) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_FULL);
            return;
        }
        JCSystem.beginTransaction();

        short phononKeyPointer = phononKeyIndex;
        byte UsingDeletedSpot = 0;

        if (DeletedPhononIndex == 0) {
            PhononArray[phononKeyPointer] = new Phonon();
            PhononArray[phononKeyPointer].ExtendedSchema = new byte[MAX_EXTENDED_SCHEMA_BUFFER];
            PhononArray[phononKeyPointer].ExtendedSchemaLength = 0;
            phononKeyIndex++;
        } else {
            DeletedPhononIndex--;
            phononKeyPointer = DeletedPhononList[DeletedPhononIndex];
            UsingDeletedSpot = 1;
        }

        PhononKey.genKeyPair();
        PhononArray[phononKeyPointer].KeyCurveType = KeyCurveType;


        ECPublicKey PhononPublicKey = (ECPublicKey) PhononKey.getPublic();
        PhononArray[phononKeyPointer].PhononPublicKeyLen = PhononPublicKey.getW(ScratchBuffer, (short) 0);

        if (UsingDeletedSpot == 0) {
            PhononArray[phononKeyPointer].sPhononPublicKey = new byte[PhononArray[phononKeyPointer].PhononPublicKeyLen];
        }
        Util.arrayCopy(ScratchBuffer, (short) 0, PhononArray[phononKeyPointer].sPhononPublicKey, (short) 0, PhononArray[phononKeyPointer].PhononPublicKeyLen);

        ECPrivateKey PhononPrivateKey = (ECPrivateKey) PhononKey.getPrivate();
        PhononArray[phononKeyPointer].PhononPrivateKeyLen = PhononPrivateKey.getS(ScratchBuffer, (short) 0);

        if (UsingDeletedSpot == 0) {
            PhononArray[phononKeyPointer].sPhononPrivateKey = new byte[PhononArray[phononKeyPointer].PhononPrivateKeyLen];
        }

        Util.arrayCopy(ScratchBuffer, (short) 0, PhononArray[phononKeyPointer].sPhononPrivateKey, (short) 0, PhononArray[phononKeyPointer].PhononPrivateKeyLen);

        //overwrite private key for security reasons
        Util.arrayFillNonAtomic(ScratchBuffer, (short)0, PhononArray[phononKeyPointer].PhononPrivateKeyLen, (byte)0x00);
        PhononArray[phononKeyPointer].Status = PHONON_STATUS_INITIALIZED;

        JCSystem.commitTransaction();

        byte[] apduBuffer;
        if (DEBUG_MODE) {
            apduBuffer = apdu.getBuffer();
        } else {
            apduBuffer = ScratchBuffer;
        }

        short off = 0;

        apduBuffer[off++] = TLV_PHONON_KEY;

        off++;
        apduBuffer[off++] = TLV_PHONON_INDEX;
        apduBuffer[off++] = 0x02;
        Util.setShort(apduBuffer, off, (short) (phononKeyPointer + 1));
        off += 2;

        apduBuffer[off++] = TLV_PUB_KEY;
        short lenoff = off++;
        Util.arrayCopyNonAtomic(PhononArray[phononKeyPointer].sPhononPublicKey, (short) 0, apduBuffer, off, PhononArray[phononKeyPointer].PhononPublicKeyLen);
        apduBuffer[lenoff] = (byte) PhononArray[phononKeyPointer].PhononPublicKeyLen;
        off += PhononArray[phononKeyPointer].PhononPublicKeyLen;
        apduBuffer[1] = (byte) (off - 1);

        if (DEBUG_MODE) {
            apdu.setOutgoingAndSend((short) 0, off);
        } else {
            secureChannel.respond(apdu, apduBuffer, off, ISO7816.SW_NO_ERROR);
        }
    }


    private void MinePhonon( APDU apdu )
    {
        byte[] apduBuffer;
        apduBuffer = apdu.getBuffer();
        secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.isValidated()) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        MiningRarity = (short)(apduBuffer[ISO7816.OFFSET_P1] & 0x00ff);
    	ECPublicKey pk = secureChannel.GetCardPublicKey();
    	pk.getW(ScratchBuffer, (short)0);

    	// Salt is TransBuffer
    	// Hash Value is ScratchBuffer used to determine rarity

        crypto.sha512.update(ScratchBuffer, (short)1, (short)64);
       	crypto.random.generateData(TransBuffer, (short) 0, (short) 64);
       	crypto.sha512.update( TransBuffer, (short)0, (short)64);
        crypto.sha512.doFinal(ScratchBuffer, (short) 0, (short)64, ScratchBuffer, (short) 0);
        short BytesRarity = (short)(MiningRarity/8);
        short BitsRarity = (short)(MiningRarity - (short)(BytesRarity*8));
        short i;
        for(i=0; i < BytesRarity; i++)
       {
        	if(ScratchBuffer[i] != 0 )
        	{
                secureChannel.respond(apdu, (short) 0, (short)(ISO7816.SW_NO_ERROR + 1));
        		return;
        	}
        }
        short BitCheck = (short)0x00ff;
        BitCheck = (short)(BitCheck >>> BitsRarity);
        short value = ScratchBuffer[i];
        value = (short)(value & 0x00ff);
       if( value > BitCheck)
        {
    	   	secureChannel.respond(apdu, (short) 0, (short)(ISO7816.SW_NO_ERROR + 1));
    		return;
        }
        // Found Rarity .. so how rare?

       while( ScratchBuffer[i] == 0)
       {
    	   if( i > 63 )
    	   {
    		   BytesRarity--;
    		   i--;
    		   break;
    	   }
    	   BytesRarity++;
    	   i++;
       }
       if(  i < 63 )
       {
    	   // how many bits are rare
    	   BitsRarity =0;
    	   BitCheck = (short)0x00ff;
    	   BitCheck = (short)(BitCheck>>>1);
    	   value = ScratchBuffer[i];
           value = (short)(value & 0x00ff);
    	   for( i = 0; i < 8;i++)
    	   {
    		   if( value > BitCheck)
    			   break;
        	   BitCheck = (short)(BitCheck>>>1);
        	   BitsRarity++;
    	   }
       }

       BitsRarity = (short)(BitsRarity + (short)(BytesRarity*8));

       if( BitsRarity > 0xff)
    	   BitsRarity = 0xff;

        JCSystem.beginTransaction();


        short phononKeyPointer = phononKeyIndex;
        byte UsingDeletedSpot = 0;

        if (DeletedPhononIndex == 0) {
            PhononArray[phononKeyPointer] = new Phonon();
            PhononArray[phononKeyPointer].ExtendedSchema = new byte[MAX_EXTENDED_SCHEMA_BUFFER];
            PhononArray[phononKeyPointer].ExtendedSchemaLength = 0;
            phononKeyIndex++;
        } else {
            DeletedPhononIndex--;
            phononKeyPointer = DeletedPhononList[DeletedPhononIndex];
            UsingDeletedSpot = 1;
        }

        PhononArray[phononKeyPointer].KeyCurveType = KEY_CURVE_TYPE_NATIVE;
        PhononArray[phononKeyPointer].CurrencyType = KEY_CURRENCY_TYPE_NATIVE;
        PhononArray[phononKeyPointer].PhononPublicKeyLen = 64;
        PhononArray[phononKeyPointer].ValueExponent = 0;
        PhononArray[phononKeyPointer].ValueBase = (byte)(BitsRarity & 0x00ff);;

        if (UsingDeletedSpot == 0) {
            PhononArray[phononKeyPointer].sPhononPublicKey = new byte[PhononArray[phononKeyPointer].PhononPublicKeyLen];
        }

        // 64 bytes of Hash ( ScratchBuffer ) is public key value

        Util.arrayCopyNonAtomic(ScratchBuffer, (short) 0, PhononArray[phononKeyPointer].sPhononPublicKey, (short) 0, (short)64);

        PhononArray[phononKeyPointer].PhononPrivateKeyLen = (short)64;
        if (UsingDeletedSpot == 0) {
            PhononArray[phononKeyPointer].sPhononPrivateKey = new byte[PhononArray[phononKeyPointer].PhononPrivateKeyLen];
        }

        // 64 byte of Salt ( TransBuffer ) is private key value

        Util.arrayCopyNonAtomic(TransBuffer, (short) 0, PhononArray[phononKeyPointer].sPhononPrivateKey, (short) 0, (short)64);

        short SigLen = secureChannel.CardSignData(ScratchBuffer, (short)64,TransBuffer, (short) 0);


        PhononArray[phononKeyPointer].ExtendedSchema[0]= TLV_EXTENDED_NATIVE_SIGNATURE;

        //allocate 2 extra bytes for the TL
        PhononArray[phononKeyPointer].ExtendedSchema[1] = (byte)(SigLen);
        Util.arrayCopyNonAtomic(TransBuffer, (short)0, PhononArray[phononKeyPointer].ExtendedSchema, (short)2, SigLen);
        PhononArray[phononKeyPointer].Status = PHONON_STATUS_INITIALIZED;

        JCSystem.commitTransaction();

        short off = 0;

        ScratchBuffer[off++] = TLV_PHONON_KEY;

        off++;
        ScratchBuffer[off++] = TLV_PHONON_INDEX;
        ScratchBuffer[off++] = 0x02;
        Util.setShort(ScratchBuffer, off, (short) (phononKeyPointer + 1));
        off += 2;

        ScratchBuffer[off++] = TLV_PUB_KEY;
        short lenoff = off++;
        Util.arrayCopyNonAtomic(PhononArray[phononKeyPointer].sPhononPublicKey, (short) 0, ScratchBuffer, off, PhononArray[phononKeyPointer].PhononPublicKeyLen);
        ScratchBuffer[lenoff] = (byte)PhononArray[phononKeyPointer].PhononPublicKeyLen;
        off += PhononArray[phononKeyPointer].PhononPublicKeyLen;
        ScratchBuffer[1] = (byte) (off - 1);

        secureChannel.respond(apdu, ScratchBuffer, (short) off, ISO7816.SW_NO_ERROR);
    	return;
    }

    /**
     * Optional receive whitelist, to allow a terminal to pre-approve which phonons should be accepted in a transfer.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void SetReceivePhononList(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.isValidated()) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }


        if (phononKeyIndex >= MAX_NUMBER_PHONONS) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_FULL);
            return;
        }

        if (ScratchBuffer[0] != TLV_PHONON_PUB_KEY_LIST) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            return;
        }
/*		Temp remove .... further discussion
        Bertlv SetReceivePhononTLV = globalBertlv;
        short PhononCount = SetReceivePhononTLV.GetLength();
        PhononCount = (short) (PhononCount / 65);
        short Offset = 0;
        for (short i = 0; i < PhononCount; i++) {
            Bertlv ListPhononTLV = BertlvArray[1];
            ListPhononTLV.LoadNextTag(SetReceivePhononTLV.GetData(), Offset);
            Offset = ListPhononTLV.bertag.nextData;
            if (ListPhononTLV.GetTag() != TLV_PHONON_PUBLIC_KEY) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            }
            SetReceiveListPubKey = JCSystem.makeTransientByteArray(ListPhononTLV.GetLength(), JCSystem.CLEAR_ON_RESET);
            Util.arrayCopyNonAtomic(ListPhononTLV.GetData(), (short) 0, SetReceiveListPubKey, (short) 0, ListPhononTLV.GetLength());
            SetReceiveList = true;
        }
*/
        if (!DEBUG_MODE) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
        }
    }

    /**
     * Process and receive an encrypted transaction, containing a transfer of some phonons.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void ReceivePhonons(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, ScratchBuffer, (short) 0, len);
        } else {
            secureChannel.preprocessAPDU(apduBuffer);
            len = (short) ((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, ScratchBuffer, (short) 0, len);

            secureChannel.CardDecrypt(ScratchBuffer, len);

            if (!pin.isValidated()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }

        }

        if (phononKeyIndex >= MAX_NUMBER_PHONONS) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
            return;
        }

        // Patch
        Bertlv PhononTLV = new Bertlv();
//        Bertlv PhononTLV = globalBertlv;

        byte[] IncomingPhonons = ScratchBuffer;

        if (IncomingPhonons[0] != TLV_PHONON_TRANSFER_PACKET) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        short PhononReceiveLength = (short) (IncomingPhonons[1] & (short) 0x00FF);
        short Offset = 2;
        byte[] TempPrivateKey = TransBuffer;
        short TempExtendedSchemaOffset = 0;
        short PhononIndex = (short) 0xffff;
        byte SchemaVersion = (byte) 0xff;
        byte ExtendedSchemaVersion = (byte) 0xff;
        short CurrencyType = (short) 0xffff;
        byte ValueBase = (byte) 0xff;
        byte ValueExponent = (byte) 0xff;
        byte KeyCurveType = (byte) 0xff;
        short TempPrivateKeyLen = 0;

        while (Offset < PhononReceiveLength) {
            if (phononKeyIndex >= MAX_NUMBER_PHONONS) {
                ISOException.throwIt(ISO7816.SW_FILE_FULL);
                return;
            }

            if (IncomingPhonons[Offset] != TLV_PHONON_PRIVATE_DESCRIPTOR) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                return;
            }
            Offset++;
            short PhononLength = (short) (IncomingPhonons[Offset] & (short) 0x00FF);
            Offset++;

            short TableCount = PhononTLV.BuildTagTable(IncomingPhonons, Offset, PhononLength);
            TempExtendedSchemaOffset = 0;
            SchemaVersion = (byte) 0xff;
            ExtendedSchemaVersion = (byte) 0xff;
            CurrencyType = (short) 0xffff;
            ValueBase = (byte) 0xff;
            ValueExponent = (byte) 0xff;
            KeyCurveType = (byte) 0xff;
            TempPrivateKeyLen = 0;
            byte[] tempPtr;

            for (short index = 0; index < TableCount; index++) {
                PhononTLV.LoadTagFromTable(IncomingPhonons, index);
                tempPtr = PhononTLV.GetData();
                switch (PhononTLV.GetTag()) {
                    case TLV_KEY_CURVE_TYPE: {
                        KeyCurveType = tempPtr[0];
                        break;
                    }

                    case TLV_PRIV_KEY: {
                        TempPrivateKeyLen = PhononTLV.GetLength();
                        Util.arrayCopyNonAtomic(tempPtr, (short) 0, TempPrivateKey, (short) 0, TempPrivateKeyLen);
                        break;
                    }

                    case TLV_SCHEMA_VERSION: {

                        SchemaVersion = tempPtr[0];
                        break;
                    }

                    case TLV_EXTENDED_SCHEMA_VERSION: {
                        ExtendedSchemaVersion = tempPtr[0];
                        break;
                    }

                    case TLV_SET_PHONON_CURRENCY: {
                        CurrencyType = Util.getShort(tempPtr, (short) 0);
                        break;
                    }

                    case TLV_SET_PHONON_VALUE: {
                        ValueBase = tempPtr[0];
                        break;
                    }

                    case TLV_VALUE_EXPONENT: {
                        ValueExponent = tempPtr[0];
                        break;
                    }

                    default: {
                        // Extended Schema Tags - need to implement
                        if (TempExtendedSchemaOffset >= MAX_EXTENDED_SCHEMA_BUFFER) {
                            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_FULL);
                            return;

                        }
                        short ExtendedOffset = PhononTLV.GetIndexDataOffset(index);
                        short ExtendedLength = (short) ((short) IncomingPhonons[(short) (ExtendedOffset + 1)] & (short) 0x00FF);
                        ExtendedLength += 2;
                        Util.arrayCopyNonAtomic(IncomingPhonons, ExtendedOffset, TempExtendedSchema, TempExtendedSchemaOffset, ExtendedLength);
                        TempExtendedSchemaOffset += ExtendedLength;
                        break;
                    }

                }
            }

            JCSystem.beginTransaction();
            short phononKeyPointer = phononKeyIndex;
            byte UsingDeletedSpot = 0;

            if (DeletedPhononIndex == 0) {
                PhononArray[phononKeyPointer] = new Phonon();
                PhononArray[phononKeyPointer].ExtendedSchema = new byte[MAX_EXTENDED_SCHEMA_BUFFER];
                PhononArray[phononKeyPointer].ExtendedSchemaLength = 0;
                phononKeyIndex++;
            } else {
                DeletedPhononIndex--;
                phononKeyPointer = DeletedPhononList[DeletedPhononIndex];
                UsingDeletedSpot = 1;
            }
            ECPrivateKey PrivateKey = (ECPrivateKey) PhononKey.getPrivate();
            PhononArray[phononKeyPointer].PhononPrivateKeyLen = TempPrivateKeyLen;

            if (UsingDeletedSpot == 0) {
                PhononArray[phononKeyPointer].sPhononPrivateKey = new byte[PhononArray[phononKeyPointer].PhononPrivateKeyLen];
            }

            Util.arrayCopyNonAtomic(TempPrivateKey, (short) 0, PhononArray[phononKeyPointer].sPhononPrivateKey, (short) 0, TempPrivateKeyLen);
            PrivateKey.setS(PhononArray[phononKeyPointer].sPhononPrivateKey, (short) 0, PhononArray[phononKeyPointer].PhononPrivateKeyLen);
            byte[] PublicKeystr = TempPrivateKey;

            short PublicKeyLength = secp256k1.derivePublicKey(PrivateKey, PublicKeystr, (short) 0);
            ECPublicKey PublicKey = (ECPublicKey) PhononKey.getPublic();
            PublicKey.setW(PublicKeystr, (short) 0, PublicKeyLength);

            PhononArray[phononKeyPointer].PhononPublicKeyLen = PublicKeyLength;

            if (UsingDeletedSpot == 0) {
                PhononArray[phononKeyPointer].sPhononPublicKey = new byte[PhononArray[phononKeyPointer].PhononPublicKeyLen];
            }
            Util.arrayCopyNonAtomic(PublicKeystr, (short) 0, PhononArray[phononKeyPointer].sPhononPublicKey, (short) 0, PhononArray[phononKeyPointer].PhononPublicKeyLen);

            PhononArray[phononKeyPointer].CurrencyType = CurrencyType;
            PhononArray[phononKeyPointer].KeyCurveType = KeyCurveType;
            PhononArray[phononKeyPointer].SchemaVersion = SchemaVersion;
            PhononArray[phononKeyPointer].ExtendedSchemaVersion = ExtendedSchemaVersion;
            PhononArray[phononKeyPointer].CurrencyType = CurrencyType;
            PhononArray[phononKeyPointer].ValueBase = ValueBase;
            PhononArray[phononKeyPointer].ValueExponent = ValueExponent;

            // Check to make sure generated public key matches what was sent by SET_RECV_LIST
// Removed for alpha
            PhononArray[phononKeyPointer].Status = PHONON_STATUS_INITIALIZED;

            JCSystem.commitTransaction();
            Offset += PhononLength;
        }
    }

    /**
     * Destroy a phonon to export its private key.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void DestroyPhonon(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);
            if (!pin.isValidated()) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }

        byte[] IncomingData = ScratchBuffer;
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short) 0, len);
        if (len > 4) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_LENGTH);
            return;
        }

        Bertlv berPhononIndex = globalBertlv;
        byte[] IncomingPhonon = IncomingData;

        berPhononIndex.LoadTag(IncomingPhonon);
        if (berPhononIndex.GetTag() != TLV_SET_PHONON_KEY_INDEX) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            return;
        }

        if (IncomingPhonon[0] != TLV_SET_PHONON_KEY_INDEX) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            return;
        }
        short PhononIndex = Util.getShort(IncomingPhonon, (short) 2);

        if (PhononIndex == 0) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;
        }
        PhononIndex--;
        if (PhononIndex >= phononKeyIndex) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;
        }

        if (PhononArray[PhononIndex] == null || PhononArray[PhononIndex].Status == PHONON_STATUS_DELETED) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;
        }

        JCSystem.beginTransaction();

        Bertlv berPhononKey = globalBertlv;
        byte[] OutgoingData = ScratchBuffer;

        berPhononKey.BuildTLVStructure(TLV_KEY_CURVE_TYPE, (short) 1, PhononArray[PhononIndex].KeyCurveType, OutgoingData, (short) 0);
        berPhononKey.BuildTLVStructure(TLV_PRIV_KEY, PhononArray[PhononIndex].PhononPrivateKeyLen, PhononArray[PhononIndex].sPhononPrivateKey, OutgoingData, (short) 3);

        PhononArray[PhononIndex].Status = PHONON_STATUS_DELETED;
        PhononArray[PhononIndex].CurrencyType = 0;
        // overwrite private key with zeros -- non-atomic, so power loss between this and send phonon will break it.
        Util.arrayFillNonAtomic(PhononArray[PhononIndex].sPhononPrivateKey, (short)0, PhononArray[PhononIndex].PhononPrivateKeyLen, (byte)0);

        DeletedPhononList[DeletedPhononIndex] = PhononIndex;
        DeletedPhononIndex++;

        JCSystem.commitTransaction();

        if (!DEBUG_MODE) {
            secureChannel.respond(apdu, OutgoingData, (short) (berPhononKey.BuildLength + 3), ISO7816.SW_NO_ERROR);
        }
    }

    /**
     * Finalize a newly created phonon, by setting a descriptor with details about the asset it encumbers.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void SetPhononDescriptor(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);

            if (!pin.isValidated()) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }
        byte[] IncomingData = ScratchBuffer;
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short) 0, len);

        Bertlv Phonon = globalBertlv;
        short TempExtendedSchemaOffset = 0;

        short TableCount = Phonon.BuildTagTable(IncomingData, (short) 0, len);
        short PhononIndex = (short) 0xffff;
        byte SchemaVersion = (byte) 0xff;
        byte ExtendedSchemaVersion = (byte) 0xff;
        short CurrencyType = (short) 0xffff;
        byte ValueBase = (byte) 0xff;
        byte ValueExponent = (byte) 0xff;
        boolean ValueBaseSet = false;
        boolean ValueExponentSet = false;

        for (short index = 0; index < TableCount; index++) {
            Phonon.LoadTagFromTable(IncomingData, index);
            switch (Phonon.GetTag()) {
                case TLV_SET_PHONON_KEY_INDEX: {
                    PhononIndex = Util.getShort(Phonon.GetData(), (short) 0);
                    break;
                }

                case TLV_SCHEMA_VERSION: {

                    SchemaVersion = (Phonon.GetData())[0];
                    break;
                }

                case TLV_EXTENDED_SCHEMA_VERSION: {
                    ExtendedSchemaVersion = (Phonon.GetData())[0];
                    break;
                }

                case TLV_SET_PHONON_CURRENCY: {
                    CurrencyType = Util.getShort(Phonon.GetData(), (short) 0);
                    break;
                }

                case TLV_SET_PHONON_VALUE: {
                    ValueBase = (Phonon.GetData())[0];
                    ValueBaseSet = true;
                    break;
                }

                case TLV_VALUE_EXPONENT: {
                    ValueExponent = (Phonon.GetData())[0];
                    ValueExponentSet = true;
                    break;
                }

                default: {
                    // Extended Schema Tags - need to implement
                    if (TempExtendedSchemaOffset >= MAX_EXTENDED_SCHEMA_BUFFER) {
                        secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_FULL);
                        return;

                    }
                    short ExtendedOffset = Phonon.GetIndexDataOffset(index);
                    short ExtendedLength = (short) ((short) IncomingData[(short) (ExtendedOffset + 1)] & (short) 0x00FF);
                    ExtendedLength += 2;
                    Util.arrayCopyNonAtomic(IncomingData, ExtendedOffset, TempExtendedSchema, TempExtendedSchemaOffset, ExtendedLength);
                    TempExtendedSchemaOffset += ExtendedLength;
                    break;
                }

            }
        }
        if (PhononIndex == (short) 0xffff) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            return;
        }
        if (PhononIndex == 0) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;
        }
        PhononIndex--;

        if (PhononIndex >= phononKeyIndex) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;
        }

        if (PhononArray[PhononIndex] == null) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;

        }

        if (SchemaVersion == UNINITIALIZED_BYTE ||
                CurrencyType > KEY_CURRENCY_TYPE_MAX ||
                ExtendedSchemaVersion == UNINITIALIZED_SHORT ||
                ValueBaseSet == false ||
                ValueExponentSet == false) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_DATA_INVALID);
            return;
        }

        JCSystem.beginTransaction();

        PhononArray[PhononIndex].CurrencyType = CurrencyType;
        PhononArray[PhononIndex].SchemaVersion = SchemaVersion;
        PhononArray[PhononIndex].ExtendedSchemaVersion = ExtendedSchemaVersion;
        PhononArray[PhononIndex].ValueBase = ValueBase;
        PhononArray[PhononIndex].ValueExponent = ValueExponent;

        if (TempExtendedSchemaOffset > 0) {
            Util.arrayCopyNonAtomic(TempExtendedSchema, (short) 0, PhononArray[PhononIndex].ExtendedSchema, (short) 0, TempExtendedSchemaOffset);
            PhononArray[PhononIndex].ExtendedSchemaLength = TempExtendedSchemaOffset;

        } else {
            PhononArray[PhononIndex].ExtendedSchemaLength = 0;
        }

        JCSystem.commitTransaction();

        if (!DEBUG_MODE) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
        }
    }


    /**
     * Fetch a phonon's public key by key index
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void GetPhononPublicKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);
            if (!pin.isValidated()) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }

        byte[] IncomingData = ScratchBuffer;
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short) 0, len);

        if (len > 4) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_LENGTH);
            return;
        }

        Bertlv berPhononIndex = globalBertlv;
        berPhononIndex.Clean();
        berPhononIndex.LoadTag(IncomingData);

        if (berPhononIndex.GetTag() != TLV_PHONON_INDEX) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            return;
        }
        short PhononIndex = Util.getShort(berPhononIndex.GetData(), (short) 0);

        if (PhononIndex == 0) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_FILE_INVALID);
            return;
        }
        PhononIndex--;

        if (PhononIndex >= phononKeyIndex) {
            secureChannel.respond(apdu, (short) 0, (short) (ISO7816.SW_FILE_INVALID + 1));
            return;
        }

        if (PhononArray[PhononIndex] == null) {
            secureChannel.respond(apdu, (short) 0, (short) (ISO7816.SW_FILE_INVALID + 2));
            return;
        }

        Bertlv berPhononKey = globalBertlv;

        byte[] OutgoingBuffer;

        if (DEBUG_MODE) {
            OutgoingBuffer = apduBuffer;
        } else {
            OutgoingBuffer = ScratchBuffer;
        }

        short offset = 0;
        OutgoingBuffer[offset] = TLV_PHONON_TRANSFER_PACKET;
        offset++;
        OutgoingBuffer[offset] = (byte) 0x00;
        offset++;
        OutgoingBuffer[offset] = TLV_PHONON_PRIVATE_DESCRIPTOR;
        offset++;
        OutgoingBuffer[offset] = 0x00;
        offset++;
        berPhononKey.BuildTLVStructure(TLV_KEY_CURVE_TYPE, (short) 1, PhononArray[PhononIndex].KeyCurveType, OutgoingBuffer, offset);
        offset += 3;
        berPhononKey.BuildTLVStructure(TLV_PUB_KEY, PhononArray[PhononIndex].PhononPublicKeyLen, PhononArray[PhononIndex].sPhononPublicKey, OutgoingBuffer, offset);
        offset += PhononArray[PhononIndex].PhononPublicKeyLen + 2;

        OutgoingBuffer[1] = (byte) (offset - 2);
        OutgoingBuffer[3] = (byte) (offset - 4);

        if (DEBUG_MODE) {
            apdu.setOutgoingAndSend((short) 0, offset);
        } else {
            secureChannel.respond(apdu, OutgoingBuffer, offset, ISO7816.SW_NO_ERROR);
        }
    }


    /**
     * Iterate the full list of phonons, returning 'N' phonons at a time. Optional list filters may be applied.
     *
     * @param apdu apdu the JCRE-owned APDU object.
     */
    private void ListPhonons(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte PhononListContinue = apduBuffer[ISO7816.OFFSET_P1];
        byte PhononFilter = apduBuffer[ISO7816.OFFSET_P2];
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);
        }

        if (len == 0 && PhononListContinue == 0 && PhononFilter != LIST_FILTER_ALL) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
            return;
        }

        if (!DEBUG_MODE) {
            if (!pin.isValidated()) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }

        if (PhononListContinue > 1) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        byte[] IncomingData = ScratchBuffer;

        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short) 0, len);

        short PhononCoinType = KEY_CURRENCY_TYPE_UNDEFINED;

        short PhononLessThanValue;
        short PhononGreaterThanValue;

        if (PhononListContinue == 0x00) {
            if (PhononFilter > LIST_FILTER_LAST) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_INCORRECT_P1P2);
                return;
            }
            if (PhononFilter != LIST_FILTER_ALL) {
                Bertlv PhononFilterTLV = globalBertlv;
                if (IncomingData[0] != TLV_PHONON_FILTER) {
                    secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
                    return;
                }
                short TableCount = PhononFilterTLV.BuildTagTable(IncomingData, (short) 2, len);
                for (short index = 0; index < TableCount; index++) {
                    PhononFilterTLV.LoadTagFromTable(IncomingData, index);
                    switch (PhononFilterTLV.GetTag()) {
                        case TLV_SET_PHONON_CURRENCY: {
                            PhononCoinType = Util.getShort(PhononFilterTLV.GetData(), (short) 0);
                            break;
                        }
                        case TLV_PHONON_LESS_THAN: {
                            PhononLessThanValue = Util.getShort(PhononFilterTLV.GetData(), (short) 0);
                            break;
                        }
                        case TLV_PHONON_GREATER_THAN: {
                            PhononGreaterThanValue = Util.getShort(PhononFilterTLV.GetData(), (short) 0);
                            break;
                        }
                    }
                }
            }
            PhononListCount = 0;
            PhononListLastSent = 0;
            switch (PhononFilter) {
                case LIST_FILTER_ALL: {
                    for (short i = 0; i < phononKeyIndex; i++) {
                        if (PhononArray[i] != null && PhononArray[i].Status == PHONON_STATUS_INITIALIZED) {
                            if (PhononCoinType == 0 || PhononCoinType == PhononArray[i].CurrencyType) {
                                PhononList[PhononListCount] = i;
                                PhononListCount++;
                            }
                        }
                    }
                    break;
                }
                case LIST_FILTER_LESS_THAN: {
                    for (short i = 0; i < phononKeyIndex; i++) {
                        if (PhononArray[i] != null && PhononArray[i].Status == PHONON_STATUS_INITIALIZED) {
                            if ((PhononCoinType == 0 && PhononArray[i].CurrencyType != 0) || PhononCoinType == PhononArray[i].CurrencyType) {
/* Discussion needed regarding filtering with generic
                                 if (Util.arrayCompare(PhononArray[i].Value, (short) 0, PhononLessThanValue, (short) 0, (short) 4) != 1) {
                                    PhononList[PhononListCount] = i;
                                    PhononListCount++;
                               }
*/
                            }
                        }
                    }
                    break;
                }
                case LIST_FILTER_GREATER_THAN: {
                    for (short i = 0; i < phononKeyIndex; i++) {
                        if (PhononArray[i] != null && PhononArray[i].Status == PHONON_STATUS_INITIALIZED) {
                            if ((PhononCoinType == 0 && PhononArray[i].CurrencyType != 0) || PhononCoinType == PhononArray[i].CurrencyType) {
/* Discussion needed regarding filtering with generic
                                if (Util.arrayCompare(PhononArray[i].Value, (short) 0, PhononGreaterThanValue, (short) 0, (short) 4) != -1) {
                                    PhononList[PhononListCount] = i;
                                    PhononListCount++;
                              }
*/
                            }
                        }
                    }
                    break;
                }
                case LIST_FILTER_GT_AND_LT: {
                    for (short i = 0; i < phononKeyIndex; i++) {
                        if (PhononArray[i] != null && PhononArray[i].Status == PHONON_STATUS_INITIALIZED) {
                            if ((PhononCoinType == 0 && PhononArray[i].CurrencyType != 0) || PhononCoinType == PhononArray[i].CurrencyType) {
/* Discussion needed regarding filtering with generic
                                if (Util.arrayCompare(PhononArray[i].Value, (short) 0, PhononLessThanValue, (short) 0, (short) 4) != 1) {
                                    if (Util.arrayCompare(PhononArray[i].Value, (short) 0, PhononGreaterThanValue, (short) 0, (short) 4) != -1) {
                                        PhononList[PhononListCount] = i;
                                        PhononListCount++;
                                    }

                               }
*/
                            }
                        }
                    }
                    break;
                }
            }
        }

        SendSelectPhononList(apdu);
    }

    /**
     * Send off phonons that have been marked for sending by listPhonons
     *
     * @param apdu apdu the JCRE-owned APDU object.
     */
    private void SendSelectPhononList(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        byte[] PhononCollection = ScratchBuffer;

        short PhononCollectionOffset = 0;
        short i, j;
        short PhononDescriptorOffset = 0;
        short PhononDescriptorLength = 0;

        for (j = PhononListLastSent; j < PhononListCount; j++) {
            i = PhononList[j];

            Bertlv berPhononDescriptor = globalBertlv;

            PhononCollection[PhononCollectionOffset] = TLV_SET_PHONON_DESCRIPTOR;
            PhononDescriptorOffset = (short) (PhononCollectionOffset + 1);
            PhononCollectionOffset += 2;

            PhononDescriptorLength = PhononCollectionOffset;
            berPhononDescriptor.BuildTLVStructure(TLV_SET_PHONON_KEY_INDEX, (short) 2, (short) (i + 1), PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 4;
            berPhononDescriptor.BuildTLVStructure(TLV_KEY_CURVE_TYPE, (short) 1, PhononArray[i].KeyCurveType, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 3;
            berPhononDescriptor.BuildTLVStructure(TLV_SCHEMA_VERSION, (short) 1, PhononArray[i].SchemaVersion, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 3;
            berPhononDescriptor.BuildTLVStructure(TLV_EXTENDED_SCHEMA_VERSION, (short) 1, PhononArray[i].ExtendedSchemaVersion, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 3;
            berPhononDescriptor.BuildTLVStructure(TLV_SET_PHONON_CURRENCY, (short) 2, PhononArray[i].CurrencyType, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 4;
            berPhononDescriptor.BuildTLVStructure(TLV_VALUE_BASE, (short) 1, PhononArray[i].ValueBase, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 3;
            berPhononDescriptor.BuildTLVStructure(TLV_VALUE_EXPONENT, (short) 1, PhononArray[i].ValueExponent, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 3;

            if (PhononArray[i].ExtendedSchemaLength != 0) {
                Util.arrayCopyNonAtomic(PhononArray[i].ExtendedSchema, (short) 0, PhononCollection, PhononCollectionOffset, PhononArray[i].ExtendedSchemaLength);
                PhononCollectionOffset = (short) (PhononCollectionOffset + PhononArray[i].ExtendedSchemaLength);
            }

            PhononDescriptorLength = (short) (PhononCollectionOffset - PhononDescriptorLength);
            PhononCollection[PhononDescriptorOffset] = (byte) PhononDescriptorLength;

            if (PhononCollectionOffset > (short) (190)) {
                break;
            }
        }

        Bertlv berPhononCollection = globalBertlv;
        byte[] OutgoingBuffer = apduBuffer;
        berPhononCollection.BuildTLVStructure(TLV_PHONON_COLLECTION, PhononCollectionOffset, PhononCollection, OutgoingBuffer);

        short remaining = ISO7816.SW_NO_ERROR;

        if (j < PhononListCount) {
            PhononListLastSent = (short) (j + 1);
            remaining = (short) ((short) (PhononListCount - PhononListLastSent) + ISO7816.SW_NO_ERROR);
        }

        if (DEBUG_MODE) {
            Util.arrayCopyNonAtomic(OutgoingBuffer, (short) 0, apduBuffer, (short) 0, (short) (PhononCollectionOffset + 2));
            apdu.setOutgoingAndSend((short) 0, (short) (PhononCollectionOffset + 2));
        } else {
            secureChannel.respond(apdu, OutgoingBuffer, (short) (PhononCollectionOffset + 2), remaining);
        }
    }

    /**
     * Build an encrypted transaction to transfer phonons to another card.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void SendPhonons(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short len;

        if (DEBUG_MODE) {
            len = apdu.getIncomingLength();
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);
            if (!pin.isValidated()) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }

        byte PhononListContinue = apduBuffer[ISO7816.OFFSET_P1];
        if (PhononListContinue > 1) {
            secureChannel.respond(apdu, (short) 0, ISO7816.SW_INCORRECT_P1P2);
            return;
        }

        if (PhononListContinue == 0) {
            SendPhononListCount = 0;
            SendPhononListLastSent = 0;
            byte PhononRequest = apduBuffer[ISO7816.OFFSET_P2];

            if (PhononRequest == 0) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_INCORRECT_P1P2);
                return;
            }


            Bertlv PhononListTLV = globalBertlv;
            byte[] IncomingPhonon = ScratchBuffer;
            Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingPhonon, (short) 0, len);
            PhononListTLV.LoadTag(IncomingPhonon);

            if (PhononListTLV.GetTag() != TLV_PHONON_INDEX_COUNT) {
                secureChannel.respond(apdu, (short) 0, ISO7816.SW_WRONG_DATA);
                return;
            }
            SendPhononListCount = (short) (PhononListTLV.GetLength() / 2);
            short Offset = 0;

            for (short i = 0; i < SendPhononListCount; i++) {
                SendPhononList[i] = Util.getShort(PhononListTLV.GetData(), Offset);
                Offset += 2;
            }
        }

        SendPhononList(apdu);
    }

    /**
     * Send off phonons with private keys of phonons that have been marked for sending by SendPhonons
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void SendPhononList(APDU apdu) {
        byte[] PhononCollection = ScratchBuffer;
        short PhononCollectionOffset = 0;

        short i, j;

        JCSystem.beginTransaction();

        for (j = SendPhononListLastSent; j < SendPhononListCount; j++) {
            i = SendPhononList[j];
            i--;

            short PhononDescriptorOffset = 0;
            short PhononDescriptorLength = 0;

            PhononCollection[PhononCollectionOffset] = TLV_PHONON_PRIVATE_DESCRIPTOR;
            PhononDescriptorOffset = (short) (PhononCollectionOffset + 1);
            PhononCollectionOffset += 2;


            Bertlv berPhonon = globalBertlv;
            berPhonon.BuildTLVStructure(TLV_PRIV_KEY, PhononArray[i].PhononPrivateKeyLen, PhononArray[i].sPhononPrivateKey, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + PhononArray[i].PhononPrivateKeyLen;
            berPhonon.BuildTLVStructure(TLV_KEY_CURVE_TYPE, (short) 1, PhononArray[i].KeyCurveType, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + 1;
            berPhonon.BuildTLVStructure(TLV_SCHEMA_VERSION, (short) 1, PhononArray[i].SchemaVersion, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + 1;
            berPhonon.BuildTLVStructure(TLV_EXTENDED_SCHEMA_VERSION, (short) 1, PhononArray[i].ExtendedSchemaVersion, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + 1;
            berPhonon.BuildTLVStructure(TLV_SET_PHONON_CURRENCY, (short) 2, PhononArray[i].CurrencyType, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + 2;
            berPhonon.BuildTLVStructure(TLV_VALUE_BASE, (short) 1, PhononArray[i].ValueBase, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + 1;
            berPhonon.BuildTLVStructure(TLV_VALUE_EXPONENT, (short) 1, PhononArray[i].ValueExponent, PhononCollection, PhononCollectionOffset);
            PhononCollectionOffset += 2 + 1;

            if (PhononArray[i].ExtendedSchemaLength != 0) {
                Util.arrayCopyNonAtomic(PhononArray[i].ExtendedSchema, (short) 0, PhononCollection, PhononCollectionOffset, PhononArray[i].ExtendedSchemaLength);
                PhononCollectionOffset = (short) (PhononCollectionOffset + PhononArray[i].ExtendedSchemaLength);
            }

            PhononDescriptorLength = (short) (PhononCollectionOffset - PhononDescriptorLength);
            PhononCollection[PhononDescriptorOffset] = (byte) PhononDescriptorLength;

            PhononArray[i].Status = PHONON_STATUS_DELETED;
            PhononArray[i].CurrencyType = 0;
            Util.arrayFillNonAtomic(PhononArray[i].sPhononPrivateKey, (short)0, PhononArray[i].PhononPrivateKeyLen, (byte)0);

            DeletedPhononList[DeletedPhononIndex] = i;
            DeletedPhononIndex++;

        }
        Bertlv berPhononCollection = globalBertlv;
        byte[] apduBuffer = apdu.getBuffer();

        berPhononCollection.BuildTLVStructure(TLV_PHONON_TRANSFER_PACKET, PhononCollectionOffset, PhononCollection, apduBuffer);
        short remaining = 0;

        if (j < SendPhononListCount) {
            SendPhononListLastSent = (short) (j + 1);
            //TODO: possibly SW_NO_ERROR is being double added here and will break things when the length exceeds one APDU
            remaining = (short) ((short) (SendPhononListCount - SendPhononListLastSent) + ISO7816.SW_NO_ERROR);
        }

        JCSystem.commitTransaction();

        if (DEBUG_MODE) {
            apdu.setOutgoingAndSend((short) 0, (short) (PhononCollectionOffset + 2));
        } else {
            short encryptLen = secureChannel.CardEncrypt(apduBuffer, (short) (PhononCollectionOffset + 2));
            apduBuffer = apdu.getBuffer();
            secureChannel.respond(apdu, apduBuffer, encryptLen, (short) (ISO7816.SW_NO_ERROR + remaining));
        }
    }

    /**
     * Select the phonon applet.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void selectApplet(APDU apdu) {
        pin.reset();
        secureChannel.reset();
        secureChannel.updateSecureChannelCounter();

        byte[] apduBuffer = apdu.getBuffer();

        short off = 0;

        apduBuffer[off++] = TLV_APPLICATION_INFO_TEMPLATE;

        if (privateKey.isInitialized()) {
            apduBuffer[off++] = (byte) 0x81;
        }

        short lenoff = off++;

        apduBuffer[off++] = TLV_UID;
        apduBuffer[off++] = UID_LENGTH;
        Util.arrayCopyNonAtomic(uid, (short) 0, apduBuffer, off, UID_LENGTH);
        off += UID_LENGTH;

        apduBuffer[off++] = TLV_PUB_KEY;
        short keyLength = secureChannel.copyPublicKey(apduBuffer, (short) (off + 1));
        apduBuffer[off++] = (byte) keyLength;
        off += keyLength;

        apduBuffer[off++] = TLV_INT;
        apduBuffer[off++] = 2;
        Util.setShort(apduBuffer, off, APPLICATION_VERSION);
        off += 2;

        apduBuffer[off++] = TLV_PAIRING_SLOT;
        apduBuffer[off++] = 1;
        apduBuffer[off++] = secureChannel.getRemainingPairingSlots();

        apduBuffer[off++] = TLV_CAPABILITIES;
        apduBuffer[off++] = 1;
        apduBuffer[off++] = APPLICATION_CAPABILITIES;

        apduBuffer[lenoff] = (byte) (off - lenoff - 1);
        apdu.setOutgoingAndSend((short) 0, off);
    }

    /**
     * Reset parameters on secp256k1 curves.
     * more curves coming.
     */
    private void resetCurveParameters() {

        secp256k1.setCurveParameters(publicKey);
        secp256k1.setCurveParameters(privateKey);

    }

    /**
     * Initialize a new card by setting the pin
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void processInit(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if (selectingApplet()) {
            apduBuffer[0] = TLV_PUB_KEY;
            apduBuffer[1] = (byte) secureChannel.copyPublicKey(apduBuffer, (short) 2);
            apdu.setOutgoingAndSend((short) 0, (short) (apduBuffer[1] + 2));
        } else if (apduBuffer[ISO7816.OFFSET_INS] == INS_INIT) {
            secureChannel.oneShotDecrypt(apduBuffer);

            if ((apduBuffer[ISO7816.OFFSET_LC] != (byte) (PIN_LENGTH + SecureChannel.SC_SECRET_LENGTH)) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            JCSystem.beginTransaction();
            secureChannel.initSecureChannel(apduBuffer, (short) (ISO7816.OFFSET_CDATA + PIN_LENGTH));

            pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
            pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);

            JCSystem.commitTransaction();
            secp256k1.setCurveParameters((ECKey) PhononKey.getPrivate());
            secp256k1.setCurveParameters((ECKey) PhononKey.getPublic());
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Utility method to verify if all the bytes in the buffer between off (included) and off + len (excluded) are digits.
     *
     * @param buffer the buffer
     * @param off    the offset to begin checking
     * @param len    the length of the data
     * @return whether all checked bytes are digits or not
     */

    private boolean allDigits(byte[] buffer, short off, short len) {
        while (len > 0) {
            len--;

            byte c = buffer[(short) (off + len)];

            if (c < 0x30 || c > 0x39) {
                return false;
            }
        }

        return true;
    }

    /**
     * Undo the card-to-card pairing process
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void unpair(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        secureChannel.preprocessAPDU(apduBuffer);

        if (pin.isValidated()) {
            secureChannel.unpair(apduBuffer);
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * Processes the VERIFY PIN command. Requires a secure channel to be already open. If a PIN longer or shorter than 6
     * digits is provided, the method will still proceed with its verification and will decrease the remaining tries
     * counter.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void verifyPIN(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len)) {
            ISOException.throwIt((short) ((short) 0x63c0 | (short) pin.getTriesRemaining()));
        }
    }

    /**
     * Processes the CHANGE PIN command. Requires a secure channel to be already open and the user PIN to be verified. All
     * PINs have a fixed format which is verified by this method.
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void changePIN(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        switch (apduBuffer[ISO7816.OFFSET_P1]) {
            case CHANGE_PIN_P1_USER_PIN:
                changeUserPIN(apduBuffer, len);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                break;
        }
    }

    /**
     * Changes the user PIN. Called internally by CHANGE PIN
     *
     * @param apduBuffer the APDU buffer
     * @param len        the data length
     */
    private void changeUserPIN(byte[] apduBuffer, byte len) {
        if (!(len == PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        pin.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
        pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len);
    }

    /**
     * Change the friendly name of the card
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void ChangeFriendlyName(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        secureChannel.preprocessAPDU(apduBuffer);
       if( (apduBuffer[ISO7816.OFFSET_LC] & 0xff) > 32 )
        {
        	secureChannel.respond(apdu, (short)0, (short)ISO7816.SW_WRONG_LENGTH);
        	return;
        }

        if (!pin.isValidated()) {
        	secureChannel.respond(apdu, (short)0, (short)ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        	return;
        }
        friendlyNameLen = apduBuffer[ISO7816.OFFSET_LC];
        Util.arrayCopy(apduBuffer, ISO7816.OFFSET_CDATA, friendlyName, (short) 0, friendlyNameLen);
        secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
    }


    /**
     * Retrieve the friendly name of the card
     *
     * @param apdu the JCRE-owned APDU object.
     */
    private void GetFriendlyName(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        if(secureChannel.isOpen())
        	secureChannel.preprocessAPDU(apduBuffer);
        if (friendlyNameLen == 0 ){
        		ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        	return;
        }
        if( secureChannel.isOpen()){
        	secureChannel.respond( apdu, friendlyName, friendlyNameLen, ISO7816.SW_NO_ERROR);
        }
        else {
            Util.arrayCopyNonAtomic(friendlyName, (short) 0, apduBuffer, (short)0, friendlyNameLen);
        	apdu.setOutgoingAndSend((short)0, friendlyNameLen);
        }
    }
}
