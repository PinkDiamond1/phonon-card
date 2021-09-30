package im.status.phonon;

import javacard.framework.*;
//
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.KeyPair;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Implements all methods related to the secure channel as specified in the SECURE_CHANNEL.md document.
 */
public class SecureChannel {
  public static final byte ID_CERTIFICATE_EMPTY = (byte) 0x00;
  public static final byte ID_CERTIFICATE_LOCKED = (byte) 0xFF;
  public static final boolean SECURE_CHANNEL_DEBUG = true;

  // cert = [permissions (2), certified pubKey (65), ECDSA signature from CA (74)]
  static final short ECDSA_MAX_LEN = 74;
  static final short PUBKEY_LEN = 65;

  // certificate format: [certType, certLen, permType, permLen, permissions(2), pubkeyType, pubkeyLen, pubkey(65), ecdsa sig (DER)]
  static final short CERTIFICATE_MAX_LEN = (short)(8 + PUBKEY_LEN + ECDSA_MAX_LEN);

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

  // This is the maximum length acceptable for plaintext commands/responses for APDUs in short format
  public static final short SC_MAX_PLAIN_LENGTH = (short) 223;

  // Card identity key & certificate
  private KeyPair idKeypair;
//  public ECPublicKey verifyPublicKey;
  private byte[] idCertificate;
  private byte idCertStatus; // EMPTY or LOCKED

  private AESKey scEncKey;
  private AESKey scMacKey;
  private Signature scMac;
  private KeyPair scKeypair;
  private Signature eccSig;
  private byte[] secret;
  private byte[] pairingSecret;

  private short scCounter;
  
  public byte[] SenderidCertificate;
  private byte	 CardidCertStatus;
  private AESKey CardscEncKey;
  private AESKey CardscMacKey;
  private byte[] Cardsecret;
  public byte[] CardAESIV;
  private byte[] SenderSalt;
  private SECP256k1 localsecp256k1;
  public byte[] CardHash;
  public byte[] CardsessionKey;
  public byte[] CardSecret;

  /*
   * To avoid overhead, the pairing keys are stored in a plain byte array as sequences of 33-bytes elements. The first
   * byte is 0 if the slot is free and 1 if used. The following 32 bytes are the actual key data.
   */
  private byte[] pairingKeys;

  private short preassignedPairingOffset = -1;
  private byte remainingSlots;
  private boolean mutuallyAuthenticated = false;

  private Crypto crypto;
  
  private byte[] DebugMasterPrivateKey = {0x00,(byte)0x90,(byte)0xf4,0x55,0x61,(byte)0xb5,(byte)0xa4,0x3d,(byte)0xa2,0x7f,0x35,0x70,0x63,0x48,(byte)0xbf,(byte)0x86,(byte)0xa4,0x75,(byte)0x9b,0x23,(byte)0x8a,0x58,(byte)0xa0,(byte)0xed,(byte)0xdb,0x24,0x2a,(byte)0xa2,0x64,(byte)0xd0,(byte)0xf0,0x2f,0x55};

  /**
   * Instantiates a Secure Channel. All memory allocations (except pairing secret) needed for the secure channel are
   * performed here. The keypair used for the EC-DH algorithm is also generated here.
   */
  public SecureChannel(byte pairingLimit, Crypto crypto, SECP256k1 secp256k1) {
    this.crypto = crypto;
    localsecp256k1 = secp256k1;
    idKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    secp256k1.setCurveParameters((ECKey) idKeypair.getPrivate());
    secp256k1.setCurveParameters((ECKey) idKeypair.getPublic());
	idKeypair.genKeyPair();
/*    if(SECURE_CHANNEL_DEBUG == false)
    {
    	idKeypair.genKeyPair();
    }
    else
    {
		ECPrivateKey idPrivateKey = (ECPrivateKey)idKeypair.getPrivate();
		idPrivateKey.setS(DebugMasterPrivateKey, (short)0, (short)32);
		byte [] PublicKeystr = new byte[100];
	    short PublicKeyLength = secp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short)0);
	    ECPublicKey PublicKey = (ECPublicKey)idKeypair.getPublic();
	    PublicKey.setW(PublicKeystr, (short)0, PublicKeyLength);
    }
*/     
    idCertificate = new byte[CERTIFICATE_MAX_LEN];
    idCertStatus = ID_CERTIFICATE_EMPTY;
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

    secret = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
//    CardsessionKey = JCSystem.makeTransientByteArray((short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
    CardsessionKey =new byte[(short)(SC_SECRET_LENGTH * 2)];
    pairingKeys = new byte[(short)(PAIRING_KEY_LENGTH * pairingLimit)];
    remainingSlots = pairingLimit;
//    CardAESIV = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
    CardAESIV = new byte[16];
//    SenderSalt = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    SenderSalt = new byte[32];
    CardHash = new byte[32];
    CardSecret = new byte[32];

  }
  
 
  public void SetDebugKey( )
  {
		ECPrivateKey idPrivateKey = (ECPrivateKey)idKeypair.getPrivate();
		idPrivateKey.setS(DebugMasterPrivateKey, (short)0, (short)32);
		byte [] PublicKeystr = new byte[70];
	    short PublicKeyLength = localsecp256k1.derivePublicKey(idPrivateKey, PublicKeystr, (short)0);
	    ECPublicKey PublicKey = (ECPublicKey)idKeypair.getPublic();
	    PublicKey.setW(PublicKeystr, (short)0, PublicKeyLength);
	    return;
  }

  /**
   * Initializes the SecureChannel instance with the pairing secret.
   *
   * @param aPairingSecret the pairing secret
   * @param off the offset in the buffer
   */
  public void initSecureChannel(byte[] aPairingSecret, short off)
  {
    if (pairingSecret != null) return;

    pairingSecret = new byte[SC_SECRET_LENGTH];
    Util.arrayCopy(aPairingSecret, off, pairingSecret, (short) 0, SC_SECRET_LENGTH);
    scKeypair.genKeyPair();
  }

  /**
   * Decrypts the content of the APDU by generating an AES key using EC-DH. Usable only with specific commands.
   * @param apduBuffer the APDU buffer
   */
  public void oneShotDecrypt(byte[] apduBuffer) {
    crypto.ecdh.init(scKeypair.getPrivate());

    short off = (short)(ISO7816.OFFSET_CDATA + 1);
    try {
      crypto.ecdh.generateSecret(apduBuffer, off, apduBuffer[ISO7816.OFFSET_CDATA], secret, (short) 0);
      off = (short)(off + apduBuffer[ISO7816.OFFSET_CDATA]);
    } catch(Exception e) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
      return;
    }

    scEncKey.setKey(secret, (short) 0);
    crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_DECRYPT, apduBuffer, off, SC_BLOCK_SIZE);
    off = (short)(off + SC_BLOCK_SIZE);

    apduBuffer[ISO7816.OFFSET_LC] = (byte) crypto.aesCbcIso9797m2.doFinal(apduBuffer, off, (short)((short)(apduBuffer[ISO7816.OFFSET_LC] & 0xff) - off + ISO7816.OFFSET_CDATA), apduBuffer, ISO7816.OFFSET_CDATA);
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
    } catch(Exception e) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
      return;
    }

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
   * @param apdu the JCRE-owned APDU object.
   */
  public void loadCert(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    if (idCertStatus != ID_CERTIFICATE_EMPTY) {
      // Card cert may only be set once and never overwritten
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    // Save the certificate
    if (apduBuffer[ISO7816.OFFSET_LC] <= (byte)CERTIFICATE_MAX_LEN) {
      Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, idCertificate, (short) 0, (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xff));
      idCertStatus = ID_CERTIFICATE_LOCKED;
    } else {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }
 
  public void SenderloadCert(byte[] IncomingCert, short IncomingCertLen ) {
	    if (CardidCertStatus != ID_CERTIFICATE_EMPTY) {
	      // Card cert may only be set once and never overwritten
	      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
	    }

	    // Save the certificate
	    if( SenderidCertificate == null)
	    {
	    	SenderidCertificate = JCSystem.makeTransientByteArray(CERTIFICATE_MAX_LEN, JCSystem.CLEAR_ON_DESELECT);
	    }
	    	
	    if (IncomingCertLen > (short)CERTIFICATE_MAX_LEN) 
	    {
		      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
	    else
	    {
	      Util.arrayCopyNonAtomic(IncomingCert, (short)0, SenderidCertificate, (short) 0, IncomingCertLen);
	      CardidCertStatus = ID_CERTIFICATE_LOCKED;
	    }
	    return;
	  }
  
  void SetSenderSalt( byte[] salt)
  {
	  Util.arrayCopyNonAtomic(salt, (short)0, SenderSalt, (short)0, (short)32);
	  return;
  }

  public byte [] GetSenderSalt( )
  {
	  return SenderSalt;
  }
  
  /**
   * Processes the IDENTIFY_CARD command. Returns the card public key, and a signature on the
   * challenge salt, to prove ownership of the key.
   * @param apdu the JCRE-owned APDU object.
   */
  public void identifyCard(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();

    // Ensure the received challenge is appropriate length
    if (apduBuffer[ISO7816.OFFSET_LC] != (byte) MessageDigest.LENGTH_SHA_256) {
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
    short sigLen = eccSig.signPreComputedHash(apduBuffer, (short) ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, apduBuffer, off);
    off += sigLen;

    // Send the response
    apdu.setOutgoingAndSend(responseStart, (short)(off - responseStart));
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

  public KeyPair GetKeyPair()
  {
	  return idKeypair;
  }
  
  public short GetCardCertificate( byte[] ReturnBuffer)
  {
	    // Copy card certificate to response buffer
	    short certLen = (short) (2 + (idCertificate[1] & 0xff));
	    Util.arrayCopyNonAtomic(idCertificate, (short) 0, ReturnBuffer, (short)0, (short) certLen);
	    return(certLen);
  }
  
  public short GetCardPublicKey( byte[] ReturnBuffer)
  {
	    ECPublicKey pk = (ECPublicKey) idKeypair.getPublic();
	    short pubkeyLen = pk.getW(ReturnBuffer, (short) (0)); // Copy pubkey after TLV type and len
	    return pubkeyLen;

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
    if (idCertStatus != ID_CERTIFICATE_LOCKED) {
      ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
      return 0;
    }

    // Override first pairing slot
    preassignedPairingOffset = 0;

    // Compute ECDH secret
    final short pubKeyOff = (short)(ISO7816.OFFSET_CDATA + SC_SECRET_LENGTH);
    try {
      crypto.ecdh.init(idKeypair.getPrivate());
      crypto.ecdh.generateSecret(apduBuffer, (short) (pubKeyOff + 2), apduBuffer[pubKeyOff + 1], secret, (short) 0);
    } catch(Exception e) {
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
    crypto.random.generateData(apduBuffer, off, SC_SECRET_LENGTH);
    off += SC_SECRET_LENGTH;
    
    // Copy card certificate to response buffer
    short certLen = (short) (2 + (idCertificate[1] & 0xff));
    Util.arrayCopyNonAtomic(idCertificate, (short) 0, apduBuffer, off, (short) certLen);
    off += certLen;

    // Sign the secret hash, and copy the signature into the response buffer
    eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
    short sigLen = eccSig.signPreComputedHash(secret, (short) 0, (short) (SC_SECRET_LENGTH), apduBuffer, off);
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
    crypto.random.generateData(apduBuffer, (short) 1, SC_SECRET_LENGTH);
    crypto.sha256.update(apduBuffer, (short) 1, SC_SECRET_LENGTH);
    crypto.sha256.doFinal(secret, (short) 0, SC_SECRET_LENGTH, pairingKeys, (short) (preassignedPairingOffset + 1));
    pairingKeys[preassignedPairingOffset] = 1;
    remainingSlots--;
    apduBuffer[0] = (byte) (preassignedPairingOffset / PAIRING_KEY_LENGTH); // Pairing index

    preassignedPairingOffset = -1;

    return (1 + SC_SECRET_LENGTH);
  }
  
  
  public void CardSenderpair(byte[] Sendersalt, short SendersaltLen, byte [] Receiversalt) {

	    // Make sure certificate exisits
	    if (idCertStatus != ID_CERTIFICATE_LOCKED) {
	      ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
	      return;
	    }

	    // Compute ECDH secret
	    short secretlen;
	    try {
	      crypto.ecdh.init(idKeypair.getPrivate());
		  byte permLen = SenderidCertificate[3];
		  byte pubKeyLen = SenderidCertificate[ 5 + permLen];
	      secretlen = crypto.ecdh.generateSecret(SenderidCertificate, (short)( 6+ permLen), pubKeyLen, CardSecret, (short) 0);
	    } catch(Exception e) {
	      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	      return;
	    }
	    
	    crypto.sha512.update(Sendersalt, (short)0 , secretlen);
	    crypto.sha512.update(Receiversalt, (short) 0, (short)32);
	    crypto.sha512.doFinal(CardSecret, (short) 0, (short)32, CardsessionKey, (short) 0);
	    CardscEncKey.setKey(CardsessionKey, (short) 0);
	    CardscMacKey.setKey(CardsessionKey, SC_SECRET_LENGTH);
	    return;
  }
  
  public short CardSignSession( byte[] CardSig)
  {
	    // Compute the expected client cryptogram, by hashing the card session key and AESIV.
	    // expectedCryptogram = sha256(CardsessionKey, CardAESIV)
	    
	    crypto.sha256.update(CardsessionKey, (short) 0, (short)(SC_SECRET_LENGTH*2));
//	    byte [] CardHash = JCSystem.makeTransientByteArray((short)32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
	    crypto.sha256.doFinal(CardAESIV, (short) 0, (short)16, CardHash, (short) 0);
	    eccSig.init(idKeypair.getPrivate(), Signature.MODE_SIGN);
	    // Sign the secret hash, and copy the signature into the response buffer
	    short sigLen = eccSig.signPreComputedHash(CardHash, (short) 0, (short) (SC_SECRET_LENGTH), CardSig, (short)0);
	    return sigLen;
  }
  
  public boolean CardVerifySession( byte [] RecieverSig, short RecieverSigLen)
  {
    crypto.sha256.update(CardsessionKey, (short) 0,(short)( SC_SECRET_LENGTH*2));
    crypto.sha256.doFinal(CardAESIV, (short) 0, (short)16, CardHash, (short) 0);
    byte permLen = SenderidCertificate[3];
    byte pubKeyLen = SenderidCertificate[ 5 + permLen];
    
    KeyPair verifyidKeypair = new KeyPair(KeyPair.ALG_EC_FP, SC_KEY_LENGTH);
    localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPrivate());
    localsecp256k1.setCurveParameters((ECKey) verifyidKeypair.getPublic());
    verifyidKeypair.genKeyPair();
    ECPublicKey pub = (ECPublicKey) verifyidKeypair.getPublic();
    localsecp256k1.setCurveParameters((ECKey)pub);
    pub.setW(SenderidCertificate, (short)( 6+ permLen), pubKeyLen);
    
    eccSig.init((ECPublicKey)pub, Signature.MODE_VERIFY);
//    boolean VerifyStatus = eccSig.verify(CardHash, (short)0, (short) (SC_SECRET_LENGTH), RecieverSig, (short)0, RecieverSigLen);
    boolean VerifyStatus = eccSig.verify(CardHash, (short)0, (short) (SC_SECRET_LENGTH), RecieverSig, (short)0, (short)(RecieverSig[(short)(1)] + 2));
    return VerifyStatus;
  }
  
  public boolean CardVerifySignature(byte [] RecieverSig, short RecieverSigLen)
  {
	   eccSig.init((ECPublicKey)idKeypair.getPublic(), Signature.MODE_VERIFY);
	    boolean VerifyStatus = eccSig.verify(CardHash, (short)0, (short) (SC_SECRET_LENGTH), RecieverSig, (short)0, RecieverSigLen);
	    return VerifyStatus;	  
  }

  public byte[] CardGetAESIV()
  {
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
  
  public byte GetCertStatus()
  {
	  return idCertStatus;
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

    short apduLen = (short)((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);

    if (!verifyAESMAC(apduBuffer, apduLen)) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_DECRYPT, secret, (short) 0, SC_BLOCK_SIZE);
    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);
    short len = crypto.aesCbcIso9797m2.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), (short) (apduLen - SC_BLOCK_SIZE), apduBuffer, ISO7816.OFFSET_CDATA);

    apduBuffer[ISO7816.OFFSET_LC] = (byte) len;

    return len;
  }

  /**
   * Verifies the AES CBC-MAC, either natively or with a software implementation. Can only be called from the
   * preprocessAPDU method since it expects the input buffer to be formatted in a particular way.
   *
   * @param apduBuffer the APDU buffer
   * @param apduLen the data len
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
   * @param len the length of the plaintext
   */
  public void respond(APDU apdu, short len, short sw) {
    byte[] apduBuffer = apdu.getBuffer();

    Util.setShort(apduBuffer, (short) (SC_OUT_OFFSET + len), sw);
    len += 2;

    crypto.aesCbcIso9797m2.init(scEncKey, Cipher.MODE_ENCRYPT, secret, (short) 0, SC_BLOCK_SIZE);
    len = crypto.aesCbcIso9797m2.doFinal(apduBuffer, SC_OUT_OFFSET, len, apduBuffer, (short)(ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE));

    apduBuffer[0] = (byte) (len + SC_BLOCK_SIZE);

    computeAESMAC(len, apduBuffer);

    Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, secret, (short) 0, SC_BLOCK_SIZE);

    len += SC_BLOCK_SIZE;
    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
  }
  
  public void respond( APDU apdu, byte[]OutgoingData, short len, short sw )
  {
	  byte[] apduBuffer = apdu.getBuffer();
	  Util.arrayCopyNonAtomic( OutgoingData, (short)0, apduBuffer, (short)SC_OUT_OFFSET, len);
	  respond( apdu, len, sw);
  }

  /**
   * Computes the AES CBC-MAC, either natively or with a software implementation. Can only be called from the respond
   * method since it expects the input buffer to be formatted in a particular way.
   *
   * @param len the data len
   * @param apduBuffer the APDU buffer
   */
  private void computeAESMAC(short len, byte[] apduBuffer) {
    scMac.init(scMacKey, Signature.MODE_SIGN);
    scMac.update(apduBuffer, (short) 0, (short) 1);
    scMac.update(secret, SC_BLOCK_SIZE, (short) (SC_BLOCK_SIZE - 1));
    scMac.sign(apduBuffer, (short) (ISO7816.OFFSET_CDATA + SC_BLOCK_SIZE), len, apduBuffer, ISO7816.OFFSET_CDATA);
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
   * @param aPairingSecret the buffer
   * @param off the offset
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
  private short checkPairingIndexAndGetOffset(byte idx) 
  {
    short off = (short) (idx * PAIRING_KEY_LENGTH);

    if (off >= ((short) pairingKeys.length))
    {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    return off;
  }
  public void SetCardidCertStatus( byte value )
  {
  	CardidCertStatus = value;
  	return;
  }
}

