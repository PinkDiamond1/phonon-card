
package im.status.phonon;

import javacard.framework.*;
import javacard.security.*;
//import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * @author MikeZercher
 *
 */
public class PhononApplet extends Applet {	//implements ExtendedLength {

	private static final boolean DEBUG_MODE	= false;
	private static final short EXTENDED_BUFFER_LENGTH = 0x10;

	static final byte PHONON_STATUS_UNINITIALIZED	= (byte) 0x00;
	static final byte PHONON_STATUS_INITIALIZED		= (byte) 0x01;
	static final byte PHONON_STATUS_PERSONALIZED	= (byte) 0x02;
	static final byte PHONON_STATUS_SENT			= (byte) 0x03;
	static final byte PHONON_STATUS_DELETED			= (byte) 0x04;

	  static final short APPLICATION_VERSION = (short) 0x0002;
	  static final byte CAPABILITY_SECURE_CHANNEL = (byte) 0x01;
	  static final byte CAPABILITY_KEY_MANAGEMENT = (byte) 0x02;
	  static final byte CAPABILITY_CREDENTIALS_MANAGEMENT = (byte) 0x04;
	  static final byte CAPABILITY_NDEF = (byte) 0x08;

//	  static final byte APPLICATION_CAPABILITIES = (byte)(CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT | CAPABILITY_NDEF);
	  static final byte APPLICATION_CAPABILITIES = (byte)(CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT );

	 static final byte INS_INIT 					= (byte) 0xFE;
	 static final byte INS_CREATE_PHONON 			= (byte) 0x30;
	 static final byte INS_SET_PHONON_DESCRIPTOR	= (byte) 0x31;
	 static final byte INS_LIST_PHONONS				= (byte) 0x32;
	 static final byte INS_GET_PHONON_PUB_KEY		= (byte) 0x33;
	 static final byte INS_DESTROY_PHONON			= (byte) 0x34;
	 static final byte INS_SEND_PHONONS				= (byte) 0x35;
	 static final byte INS_RECV_PHONONS				= (byte) 0x36;
	 static final byte INS_SET_RECV_LIST			= (byte) 0x37;
	 static final byte INS_TRANSACTION_ACK			= (byte) 0x38;
	 static final byte INS_INIT_CARD_PAIRING		= (byte) 0x50;
	 static final byte INS_CARD_SENDER_PAIR			= (byte) 0x51;
	 static final byte INS_CARD_RECEIVER_PAIR		= (byte) 0x52;
	 static final byte INS_CARD_FINALIZE			= (byte) 0x53;

	  static final byte PUK_LENGTH = 12;
	  static final byte PUK_MAX_RETRIES = 5;
	  static final byte PIN_LENGTH = 6;
	  static final byte PIN_MAX_RETRIES = 3;
	  static final byte KEY_PATH_MAX_DEPTH = 10;
	  static final byte PAIRING_MAX_CLIENT_COUNT = 1;
	  static final byte UID_LENGTH = 16;
	  // Maximum payload size of an encrypted APDU: https://status.im/keycard_api/apdu/opensecurechannel.html
	  static final short SAVED_DATA_SIZE = 223;

	  static final short CHAIN_CODE_SIZE = 32;
	  static final short KEY_UID_LENGTH = 32;
	  static final short BIP39_SEED_SIZE = CHAIN_CODE_SIZE * 2;
	  static final byte MASTERSEED_EMPTY = (byte) 0x00;
	  static final byte MASTERSEED_NOT_EXPORTABLE = (byte) 0x01;
	  static final byte MASTERSEED_EXPORTABLE = (byte) 0x02;

	  static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;

	  static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
	  static final byte TLV_PUB_KEY = (byte) 0x80;
	  static final byte TLV_PRIV_KEY = (byte) 0x81;
	  static final byte TLV_CHAIN_CODE = (byte) 0x82;
	  static final byte TLV_SEED = (byte) 0x83;
	  static final byte TLV_SEED_STATUS = (byte) 0x84;
	  static final byte TLV_DATA = (byte) 0x85;
	  static final byte TLV_PHONON_KEY = (byte) 0x40;
	  static final byte TLV_PHONON_INDEX = (byte) 0x41;

	  static final byte TLV_APPLICATION_STATUS_TEMPLATE = (byte) 0xA3;
	  static final byte TLV_PAIRING_SLOT = (byte)0x03;
	  static final byte TLV_INT = (byte) 0x02;
	  static final byte TLV_BOOL = (byte) 0x01;

	  static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;
	  static final byte TLV_UID = (byte) 0x8F;
	  static final byte TLV_KEY_UID = (byte) 0x8E;
	  static final byte TLV_CAPABILITIES = (byte) 0x8D;

	  static final byte INS_VERIFY_PIN = (byte) 0x20;
	  static final byte INS_CHANGE_PIN = (byte) 0x21;

	  static final byte CHANGE_PIN_P1_USER_PIN = 0x00;
	  static final byte CHANGE_PIN_P1_PUK = 0x01;
	  static final byte CHANGE_PIN_P1_PAIRING_SECRET = 0x02;

	  private Crypto crypto;
	  private SECP256k1 secp256k1;
	  private SecureChannel secureChannel;

      private byte[] uid;
	  private byte[] savedData;
	  private byte masterSeedStatus; // Invalid / valid, but non-exportable / valid and exportable

	  private ECPublicKey masterPublic;
	  private ECPrivateKey masterPrivate;
	  private byte[] masterChainCode;
	  private boolean isExtended;

	  private ECPublicKey parentPublicKey;
	  private ECPrivateKey parentPrivateKey;
	  private byte[] parentChainCode;

	  private ECPublicKey publicKey;
	  private ECPrivateKey privateKey;
	  private byte[] chainCode;

	  private ECPublicKey pinlessPublicKey;
	  private ECPrivateKey pinlessPrivateKey;

	  private byte[] keyPath;
	  private short keyPathLen;

	  private byte[] pinlessPath;
	  private short pinlessPathLen;

	  private Signature signature;

	  private byte[] keyUID;

	  private byte[] masterSeed;
	  private byte[] duplicationEncKey;
	  private short expectedEntropy;

	  private OwnerPIN pin;
	  private byte[] OutputData;
//	  private byte[] OutputData2;

	  public static final short PHONON_KEY_LENGTH = 256;
	  public static final short MAX_NUMBER_PHONONS = 256;

	  static final byte TLV_SET_PHONON_DESCRIPTOR	= (byte)0x50;
	  static final byte TLV_PHONON_COLLECTION		= (byte)0x52;
	  static final byte TLV_PHONON_COLLECTION_COUNT = (byte)0x53;
	  static final byte TLV_PHONON_PRIVATE_DESCRIPTOR = (byte) 0x44;
	  static final byte TLV_PHONON_INDEX_COUNT		= (byte) 0x42;
	  static final byte TLV_PHONON_TRANSFER_PACKET	= (byte) 0x43;

	  static final byte TLV_PHONON_FILTER			= (byte)0x60;
	  static final byte	TLV_SET_PHONON_KEY_INDEX 	= (byte)0x41;
	  static final byte TLV_PHONON_PUB_KEY_LIST		= (byte)0x7f;
	  static final byte TLV_PHONON_PUBLIC_KEY		= (byte)0x80;
	  static final byte TLV_SET_PHONON_CURRENCY		= (byte)0x82;
	  static final byte TLV_SET_PHONON_VALUE		= (byte)0x83;
	  static final byte TLV_PHONON_LESS_THAN		= (byte)0x84;
	  static final byte TLV_PHONON_GREATER_THAN		= (byte)0x85;

	  static final byte LIST_FILTER_ALL				= (byte) 0x00;
	  static final byte LIST_FILTER_LESS_THAN		= (byte) 0x01;
	  static final byte LIST_FILTER_GREATER_THAN	= (byte) 0x02;
	  static final byte LIST_FILTER_GT_AND_LT		= (byte) 0x03;
	  static final byte LIST_FILTER_LAST			= (byte) 0x03;

	  static final short TLV_NOT_FOUND				= (short)0xffff;

	  static final byte TLV_CARD_CERTIFICATE		= (byte) 0x90;
	  static final byte TLV_SALT					= (byte) 0x91;
	  static final byte TLV_AESIV					= (byte) 0x92;
	  static final byte TLV_RECEIVER_SIG			= (byte) 0x93;

	  private short phononKeyIndex = 0;
	  private short DeletedPhononIndex = 0;

	  private Phonon2[]	PhononArray2;
	  KeyPair 			PhononKey;
	  private short[]	PhononList;
	  private short[]	SendPhononList;
	  private short[]	DeletedPhononList;

	  private short		PhononListCount;
	  private short		PhononListLastSent;
	  private short		SendPhononListCount;
	  private short		SendPhononListLastSent;
	  private boolean	SetReceiveList;
	  private byte[]	SetReceiveListPubKey;
	  private Bertlv[]	BertlvArray;

	  private byte[]	ExtendedBuffer;
	  private boolean	DebugKeySet;

	  public PhononApplet()
	  {
		    crypto = new Crypto();
		    secp256k1 = new SECP256k1(crypto);
		    secureChannel = new SecureChannel(PAIRING_MAX_CLIENT_COUNT, crypto, secp256k1);

		    uid = new byte[UID_LENGTH];
		    crypto.random.generateData(uid, (short) 0, UID_LENGTH);

		    savedData = new byte[SAVED_DATA_SIZE];

		    masterSeed = new byte[BIP39_SEED_SIZE];
		    masterSeedStatus = MASTERSEED_EMPTY;
		    PhononArray2 = new Phonon2[ MAX_NUMBER_PHONONS ];
		    PhononList = new short[ MAX_NUMBER_PHONONS ];
		    SendPhononList = new short[ MAX_NUMBER_PHONONS ];
		    DeletedPhononList = new short[ MAX_NUMBER_PHONONS ];
		    PhononListCount = 0;
		    PhononListLastSent = 0;
		    SendPhononListCount = 0;
		    SendPhononListLastSent = 0;
		    SetReceiveList = false;

		    masterPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		    masterPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

		    parentPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		    parentPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

		    publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		    privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);

		    pinlessPublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		    pinlessPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);


		    masterChainCode = new byte[CHAIN_CODE_SIZE];
		    parentChainCode = new byte[CHAIN_CODE_SIZE];
		    chainCode = new byte[CHAIN_CODE_SIZE];
		    keyPath = new byte[KEY_PATH_MAX_DEPTH * 4];
		    pinlessPath = new byte[KEY_PATH_MAX_DEPTH * 4];

		    keyUID = new byte[KEY_UID_LENGTH];

		    resetCurveParameters();

		    signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

		    duplicationEncKey = new byte[(short)(KeyBuilder.LENGTH_AES_256/8)];
		    expectedEntropy = -1;

		    OutputData = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
//		    OutputData2 = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);

		    PhononKey = new KeyPair(KeyPair.ALG_EC_FP, PHONON_KEY_LENGTH);
		    DebugKeySet = false;
 		    BertlvArray = new Bertlv[5];
		    for( short i =0; i<5 ;i++ )
		    	BertlvArray[i] = new Bertlv();
//		    ExtendedBuffer = new byte[ EXTENDED_BUFFER_LENGTH];
		  }

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
			// GP-compliant JavaCard applet registration
			new im.status.phonon.PhononApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}


	public void process(APDU apdu) throws ISOException
	{
		// Good practice: Return 9000 on SELECT
		byte[] buf = apdu.getBuffer();
	    if(secureChannel.SECURE_CHANNEL_DEBUG == true && DebugKeySet == false)
	    {
	    	secureChannel.SetDebugKey();
	    	DebugKeySet = true;
	    }

if(DEBUG_MODE)
{
	if((buf[ISO7816.OFFSET_INS] != INS_CREATE_PHONON  )
				&& (buf[ISO7816.OFFSET_INS] != INS_LIST_PHONONS )
				&& (buf[ISO7816.OFFSET_INS] != INS_DESTROY_PHONON )
				&& (buf[ISO7816.OFFSET_INS] != INS_GET_PHONON_PUB_KEY )
				&& (buf[ISO7816.OFFSET_INS] != INS_SEND_PHONONS )
				&& (buf[ISO7816.OFFSET_INS] != INS_RECV_PHONONS )
				&& (buf[ISO7816.OFFSET_INS] != INS_SET_RECV_LIST )
				&& (buf[ISO7816.OFFSET_INS] != INS_TRANSACTION_ACK )
				&& (buf[ISO7816.OFFSET_INS] != INS_INIT_CARD_PAIRING)
				&& (buf[ISO7816.OFFSET_INS] != INS_CARD_SENDER_PAIR)
				&& (buf[ISO7816.OFFSET_INS] != INS_CARD_RECEIVER_PAIR)
				&& (buf[ISO7816.OFFSET_INS] != INS_CARD_FINALIZE)
			&& 	(buf[ISO7816.OFFSET_INS] != INS_SET_PHONON_DESCRIPTOR)
				)
		{
		    if( buf[ISO7816.OFFSET_INS] != SecureChannel.INS_IDENTIFY_CARD &&
		    		buf[ISO7816.OFFSET_INS] != SecureChannel.INS_LOAD_CERT )
		    {
			      if (pin == null)
			      {
			          processInit(apdu);
			          return;
			      }

		    }
			if (selectingApplet())
			{
			      selectApplet(apdu);
			      JCSystem.requestObjectDeletion();
			      return;
			}
		}
}
else
{
    if( buf[ISO7816.OFFSET_INS] != SecureChannel.INS_IDENTIFY_CARD &&
    		buf[ISO7816.OFFSET_INS] != SecureChannel.INS_LOAD_CERT )
    {
	      if (pin == null)
	      {
	          processInit(apdu);
	          return;
	      }

    }
	if (selectingApplet())
	{
	      selectApplet(apdu);
	      JCSystem.requestObjectDeletion();
	      return;
	}
}
		try
		{
			switch (buf[ISO7816.OFFSET_INS])
			{
		        case SecureChannel.INS_IDENTIFY_CARD:
		        {
		            secureChannel.identifyCard(apdu);
		            break;
		        }
		        case SecureChannel.INS_LOAD_CERT:
		        {
		            secureChannel.loadCert(apdu);
		            break;
		        }
		        case SecureChannel.INS_OPEN_SECURE_CHANNEL:
		        {
		            secureChannel.openSecureChannel(apdu);
		            break;
		        }
		        case SecureChannel.INS_MUTUALLY_AUTHENTICATE:
		        {
		            secureChannel.mutuallyAuthenticate(apdu);
		            break;
		        }
		        case SecureChannel.INS_PAIR:
		        {
		            secureChannel.pair(apdu);
		            break;
		        }
		        case SecureChannel.INS_UNPAIR:
		        {
		            unpair(apdu);
		            break;
		        }
		        case INS_VERIFY_PIN:
		        {
		            verifyPIN(apdu);
		            break;
		        }
		        case INS_CHANGE_PIN:
		        {
		            changePIN(apdu);
		            break;
		        }
		        case INS_CREATE_PHONON:
		        {
		        	createPhonon( apdu );
		        	break;
		        }
		        case INS_SET_PHONON_DESCRIPTOR:
		        {
		        	SetPhononDescriptor( apdu);
		        	break;
		        }
		        case INS_LIST_PHONONS:
		        {
		        	ListPhonons( apdu);
			      JCSystem.requestObjectDeletion();
		        	break;
		        }

		        case INS_GET_PHONON_PUB_KEY:
		        {
		        	GetPhononPublicKey( apdu);
		        	break;
		        }

		        case INS_DESTROY_PHONON:
		        {
		        	DestroyPhonon( apdu);
		        	break;
		        }

		        case INS_SEND_PHONONS:
		        {
		        	SendPhonons( apdu );
		        	break;
		        }

		        case INS_RECV_PHONONS:
		        {
		        	ReceivePhonons( apdu );
		        	break;
		        }

		        case INS_SET_RECV_LIST:
		        {
		        	SetReceivePhononList( apdu );
		        	break;
		        }

		        case INS_TRANSACTION_ACK:
		        {
		        	SetTransactionsAsComplete( apdu );
		        	break;
		        }

		        case INS_INIT_CARD_PAIRING:
		        {
		        	InitCardPairing( apdu );
		        	break;
		        }

		        case INS_CARD_SENDER_PAIR:
		        {
		        	SenderPairing( apdu );
		        	break;
		        }

		        case INS_CARD_RECEIVER_PAIR:
		        {
		        	ReceiverPairing( apdu );
		        	break;
		        }

		        case INS_CARD_FINALIZE:
		        {
		        	FinalizeCardPairing( apdu );
		        	break;
		        }

		        default:
				// good practice: If you don't know the INStruction, say so:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}catch(ISOException sw)
		{
		      handleException(apdu, sw.getReason());
	    }catch(CryptoException ce)
	    {
	      handleException(apdu, (short)(ISO7816.SW_UNKNOWN | ce.getReason()));
	    }catch (Exception e)
	    {
	      handleException(apdu, ISO7816.SW_UNKNOWN);
	    }

	    if (shouldRespond(apdu)) {
	      secureChannel.respond(apdu, (short) 0, ISO7816.SW_NO_ERROR);
	    }
	}

	private void handleException(APDU apdu, short sw)
	  {
		if (shouldRespond(apdu) && (sw != ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED))
		{
		    secureChannel.respond(apdu, (short) 0, sw);
		}
		else
		{
		    ISOException.throwIt(sw);
		}
	}

	private boolean shouldRespond(APDU apdu)
	{
		return secureChannel.isOpen() && (apdu.getCurrentState() != APDU.STATE_FULL_OUTGOING);
	}

	private void InitCardPairing( APDU apdu )
	{
	    byte[] apduBuffer1 = apdu.getBuffer();
	    short len;
	    if(DEBUG_MODE)
		    len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer1);
	    	if (!pin.isValidated())
	    	{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
	    	}
	    }

//	    len = apdu.getIncomingLength();
	   byte [] IncomingData = apduBuffer1;

       short ptr = ISO7816.OFFSET_CDATA;

       if( IncomingData[ptr] != TLV_CARD_CERTIFICATE )
       {
    	   ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//    	   secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
   			return;
       }
       ptr++;
       short CertLen = (short)((short)IncomingData[ptr] & (short)0x00FF);
       ptr++;
       Util.arrayCopyNonAtomic(IncomingData, ptr, OutputData,(short)0, CertLen);

       secureChannel.SetCardidCertStatus((byte)0x00);
       secureChannel.SenderloadCert(OutputData, CertLen);


		byte CertStatus = secureChannel.GetCertStatus();
	    if (CertStatus == 0x00 )
	    {
	        // Card cert was not initialized
	        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
	    }

        short Offset = 0;
		byte[] apduBuffer;
		apduBuffer = apdu.getBuffer();

        short CardCertLen =secureChannel.GetCardCertificate(OutputData);
		Bertlv berCert = BertlvArray[0];
		berCert.BuildTLVStructure( TLV_CARD_CERTIFICATE, CardCertLen, OutputData, apduBuffer, Offset );
//		Util.arrayCopyNonAtomic(OutputData2, (short)0, apduBuffer, Offset, berCert.BuildLength);
		Offset += berCert.BuildLength;

		byte [] salt = new byte[32];
		if(secureChannel.SECURE_CHANNEL_DEBUG == true)
			Util.arrayFillNonAtomic(salt, (short)0, (short)32, (byte)0x01);
		else
			crypto.random.generateData(salt, (short)0, (short)32);
		secureChannel.SetSenderSalt( salt );

		Bertlv berCardSalt = BertlvArray[0];
		berCardSalt.BuildTLVStructure( TLV_SALT, (short)32, salt, apduBuffer, Offset );
//		Util.arrayCopyNonAtomic(OutputData2, (short)0, apduBuffer, Offset, berCardSalt.BuildLength);
		Offset += berCardSalt.BuildLength;

	    if( DEBUG_MODE)
	    	apdu.setOutgoingAndSend((short) 0, Offset);
	    else
	    	secureChannel.respond( apdu,  apduBuffer,  Offset, ISO7816.SW_NO_ERROR);
//	apdu.setOutgoingAndSend((short) 0, Offset);
		return;
	}

	private void SenderPairing( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if(DEBUG_MODE)
		    len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);
	    	if (!pin.isValidated())
	    	{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
	    	}
	    }

//      len = apdu.getIncomingLength();
	   byte [] IncomingData = apduBuffer;

       short ptr = ISO7816.OFFSET_CDATA;

       if( IncomingData[ptr] != TLV_CARD_CERTIFICATE )
       {
        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//    	   secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
   			return;
       }
       ptr++;
       short CertLen = (short)((short)IncomingData[ptr] & (short)0x00FF);
       ptr++;
       Util.arrayCopyNonAtomic(IncomingData, ptr, OutputData,(short)0, CertLen);

       secureChannel.SetCardidCertStatus((byte)0x00);
       secureChannel.SenderloadCert(OutputData, CertLen);
       ptr += CertLen;
       if( IncomingData[ptr] != TLV_SALT)
       {
       	    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
       }
       ptr++;
       short SenderSaltLen = IncomingData[ptr];
       ptr++;
       byte [] SenderSalt = JCSystem.makeTransientByteArray(SenderSaltLen, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
       Util.arrayCopyNonAtomic(IncomingData, ptr, SenderSalt, (short) 0, SenderSaltLen);

		byte [] Receiversalt = new byte[32];
		if(secureChannel.SECURE_CHANNEL_DEBUG == true)
			Util.arrayFillNonAtomic(Receiversalt, (short)0, (short)32, (byte)0x02);
      else
			crypto.random.generateData(Receiversalt, (short)0, (short)32);

		short Offset = 0;
		if(secureChannel.SECURE_CHANNEL_DEBUG == true)
			Util.arrayFillNonAtomic(secureChannel.CardAESIV, (short)0, (short)16, (byte)0x03);
		else
			crypto.random.generateData(secureChannel.CardAESIV, (short)0, (short)16);

		secureChannel.CardSenderpair( SenderSalt, SenderSaltLen, Receiversalt);

		apduBuffer = apdu.getBuffer();
		Bertlv berCardSalt = BertlvArray[0];
		berCardSalt.BuildTLVStructure( TLV_SALT, (short)32, Receiversalt, apduBuffer, (short)0 );
//		berCardSalt.BuildTLVStructure( TLV_SALT, (short)32, Receiversalt, OutputData2 );
//		Util.arrayCopyNonAtomic(OutputData2, (short)0, apduBuffer, Offset, berCardSalt.BuildLength);
		Offset += berCardSalt.BuildLength;

		Bertlv berCardAES = BertlvArray[0];
		berCardAES.BuildTLVStructure( TLV_AESIV, (short)16, secureChannel.CardGetAESIV(), apduBuffer, Offset);
//		berCardAES.BuildTLVStructure( TLV_AESIV, (short)16, secureChannel.CardGetAESIV(), OutputData2);
//		Util.arrayCopyNonAtomic(OutputData2, (short) 0, apduBuffer, Offset, berCardAES.BuildLength);
		Offset += berCardAES.BuildLength;

		Util.arrayFillNonAtomic(OutputData, (short)0,(short)OutputData.length, (byte)0x00);
		short sigLen = secureChannel.CardSignSession( OutputData);
		Bertlv berCardSig = BertlvArray[0];
		berCardSig.BuildTLVStructure( TLV_RECEIVER_SIG, sigLen, OutputData, apduBuffer, Offset);
//		berCardSig.BuildTLVStructure( TLV_RECEIVER_SIG, sigLen, OutputData, OutputData2);
//		Util.arrayCopyNonAtomic(OutputData2, (short) 0, apduBuffer, Offset, berCardSig.BuildLength);
		Offset += berCardSig.BuildLength;

//    	apdu.setOutgoingAndSend((short) 0, Offset);
	    if( DEBUG_MODE)
	    	apdu.setOutgoingAndSend((short) 0, Offset);
	    else
	    	secureChannel.respond( apdu,  apduBuffer,  Offset, ISO7816.SW_NO_ERROR);

		return;
	}

	private void ReceiverPairing(APDU apdu)
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if(DEBUG_MODE)
		    len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);
	    	if (!pin.isValidated())
	    	{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
	    	}
	    }

        Bertlv RecieveSaltTLV = BertlvArray[0];;
        byte[] IncomingPhonon = OutputData;
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingPhonon, (short)0,len);
        RecieveSaltTLV.LoadTag(IncomingPhonon);
        if( RecieveSaltTLV.GetTag() != TLV_SALT )
        {
        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			return;
        }
		byte [] Receiversalt = new byte[RecieveSaltTLV.GetLength()];
        Util.arrayCopyNonAtomic(RecieveSaltTLV.GetData(),(short)0,Receiversalt, (short)0, RecieveSaltTLV.GetLength());
        Bertlv RecieveAESTLV = BertlvArray[0];
        short Offset = (short)(RecieveSaltTLV.GetLength() + 2);
        RecieveAESTLV.LoadTagBase(IncomingPhonon, Offset);
        if( RecieveAESTLV.GetTag() != TLV_AESIV || RecieveAESTLV.GetLength() != 16)
        {
        	ISOException.throwIt((short)(ISO7816.SW_WRONG_DATA + 1));
			return;
        }
		Util.arrayCopyNonAtomic(RecieveAESTLV.GetData(), (short)0, secureChannel.CardAESIV, (short)0, RecieveAESTLV.GetLength());
		Offset+=(short)(RecieveAESTLV.GetLength() + 2);
        Bertlv RecieveSigTLV = BertlvArray[0];
        RecieveSigTLV.LoadTagBase(IncomingPhonon, Offset);
        if( RecieveSigTLV.GetTag() != TLV_RECEIVER_SIG)
        {
        	ISOException.throwIt((short)(ISO7816.SW_WRONG_DATA + 2));
   			return;
        }
		secureChannel.CardSenderpair( secureChannel.GetSenderSalt(),RecieveSaltTLV.GetLength() , Receiversalt);
		boolean SigVerifyStatus = secureChannel.CardVerifySession(RecieveSigTLV.GetData(), RecieveSigTLV.GetLength());
//		if( SigVerifyStatus == false)
//		{
//			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
//			return;
//		}
		Offset = 0;
		Util.arrayFillNonAtomic(OutputData, (short)0,(short)OutputData.length, (byte)0x00);
		short sigLen = secureChannel.CardSignSession( OutputData);
		Bertlv berCardSig = BertlvArray[0];
		berCardSig.BuildTLVStructure( TLV_RECEIVER_SIG, sigLen, OutputData, apduBuffer);
		Offset += berCardSig.BuildLength;

//    	apdu.setOutgoingAndSend((short) 0, Offset);
	    if( DEBUG_MODE)
	    	apdu.setOutgoingAndSend((short) 0, Offset);
	    else
	    	secureChannel.respond( apdu,  apduBuffer,  Offset, ISO7816.SW_NO_ERROR);

 		return;
	}

	private void FinalizeCardPairing( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if(DEBUG_MODE)
		    len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);
	    	if (!pin.isValidated())
	    	{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
	    	}
	    }

 //   	len = apdu.getIncomingLength();

        short ptr = ISO7816.OFFSET_CDATA;

        if( apduBuffer[ptr] != TLV_RECEIVER_SIG )
        {
     	   ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//     	   secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
    			return;
        }
        ptr++;
        short SigLen = (short)((short)apduBuffer[ptr] & (short)0x00FF);
        ptr++;
        Util.arrayCopyNonAtomic(apduBuffer, ptr, OutputData,(short)0, SigLen);
        boolean SigVerifyStatus = secureChannel.CardVerifySignature(OutputData, SigLen);
		if( SigVerifyStatus == false)
		{
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			return;
		}
		return;
	}

	private void createPhonon( APDU apdu)
	{
        secp256k1.setCurveParameters((ECKey) PhononKey.getPrivate());
	    secp256k1.setCurveParameters((ECKey) PhononKey.getPublic());
	    byte[] apduBuffer1 = apdu.getBuffer();
	    short len;

	    if(DEBUG_MODE)
		    len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer1);
	    	if (!pin.isValidated())
	    	{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
	    	}
	    }

		if( phononKeyIndex >= MAX_NUMBER_PHONONS && DeletedPhononIndex == 0)
		{
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_FULL);
			return;
		}
		JCSystem.beginTransaction();
		short phononKeyPointer = phononKeyIndex;
		byte UsingDeletedSpot = 0;
		if( DeletedPhononIndex == 0)
		{
			PhononArray2[phononKeyPointer] = new Phonon2();
			phononKeyIndex++;
		}
		else
		{
			DeletedPhononIndex--;
			phononKeyPointer = DeletedPhononList[DeletedPhononIndex];
			UsingDeletedSpot = 1;
		}

		PhononKey.genKeyPair();

		ECPublicKey	PhononPublicKey = (ECPublicKey)PhononKey.getPublic();;
		PhononArray2[phononKeyPointer].PhononPublicKeyLen = PhononPublicKey.getW(OutputData, (short)0);
		if( UsingDeletedSpot == 0 )
		{
			PhononArray2[phononKeyPointer].sPhononPublicKey = new byte[PhononArray2[phononKeyPointer].PhononPublicKeyLen];
		}
		Util.arrayCopy(OutputData, (short)0, PhononArray2[phononKeyPointer].sPhononPublicKey, (short)0, PhononArray2[phononKeyPointer].PhononPublicKeyLen);

		ECPrivateKey PhononPrivateKey = (ECPrivateKey)PhononKey.getPrivate();;
		PhononArray2[phononKeyPointer].PhononPrivateKeyLen = PhononPrivateKey.getS(OutputData, (short)0);
		if( UsingDeletedSpot == 0)
		{
			PhononArray2[phononKeyPointer].sPhononPrivateKey = new byte[PhononArray2[phononKeyPointer].PhononPrivateKeyLen];
		}
		Util.arrayCopy(OutputData, (short)0, PhononArray2[phononKeyPointer].sPhononPrivateKey, (short)0, PhononArray2[phononKeyPointer].PhononPrivateKeyLen);

		PhononArray2[phononKeyPointer].Status = PHONON_STATUS_INITIALIZED;
		JCSystem.commitTransaction();

		byte[] apduBuffer;
		if( DEBUG_MODE)
			apduBuffer = apdu.getBuffer();
		else
			apduBuffer = OutputData;

	    short off = 0;

	    apduBuffer[off++] = TLV_PHONON_KEY;

	    off++;
	    apduBuffer[off++] = TLV_PHONON_INDEX;
	    apduBuffer[off++] = 0x02;
	    Util.setShort(apduBuffer, off, (short)(phononKeyPointer + 1));
	    off += 2;

	    apduBuffer[off++] = TLV_PUB_KEY;
	    short lenoff = off++;
	    Util.arrayCopyNonAtomic(PhononArray2[phononKeyPointer].sPhononPublicKey, (short)0, apduBuffer, off, PhononArray2[phononKeyPointer].PhononPublicKeyLen);
	    apduBuffer[lenoff] = (byte) PhononArray2[phononKeyPointer].PhononPublicKeyLen;
	    off += PhononArray2[phononKeyPointer].PhononPublicKeyLen;
	    apduBuffer[ 1 ] = (byte)(off - 1);

	    if( DEBUG_MODE)
	    	apdu.setOutgoingAndSend((short) 0, off);
	    else
	    	secureChannel.respond( apdu,  apduBuffer,  off, ISO7816.SW_NO_ERROR);
	}

	private void SetReceivePhononList( APDU apdu )
	{
		byte[] apduBuffer = apdu.getBuffer();
		short len;

		if( DEBUG_MODE)
		{
			len = apdu.getIncomingLength();
		}
		else
		{
			len = secureChannel.preprocessAPDU(apduBuffer);

			if (!pin.isValidated())
			{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
			}
		}

		if(phononKeyIndex >= MAX_NUMBER_PHONONS)
		{
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_FULL);
			return;
		}
        Bertlv SetRecievePhononTLV = BertlvArray[0];
        byte[] IncomingPhonon = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);

        Util.arrayCopyNonAtomic(apduBuffer, (short)0, IncomingPhonon, (short)0,len);
        SetRecievePhononTLV.LoadTag(IncomingPhonon);
        if( SetRecievePhononTLV.GetTag() != TLV_PHONON_PUB_KEY_LIST )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
        short PhononCount = SetRecievePhononTLV.GetLength();
        PhononCount = (short)(PhononCount / 65);
        short Offset = 0;
        for( short i = 0; i < PhononCount; i++)
        {
			Bertlv ListPhononTLV = BertlvArray[1];
			ListPhononTLV.LoadNextTag(SetRecievePhononTLV.GetData(), Offset);
		    Offset = ListPhononTLV.bertag.nextData;
		    if( ListPhononTLV.GetTag() != TLV_PHONON_PUBLIC_KEY)
		    {
				secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
	        }
		    SetReceiveListPubKey = JCSystem.makeTransientByteArray(ListPhononTLV.GetLength(), JCSystem.CLEAR_ON_RESET);
		    Util.arrayCopyNonAtomic(ListPhononTLV.GetData(), (short)0, SetReceiveListPubKey, (short)0, ListPhononTLV.GetLength());
		    SetReceiveList = true;
        }
        if( DEBUG_MODE == false)
        	secureChannel.respond( apdu, (short)0, ISO7816.SW_NO_ERROR);
	}

	private void ReceivePhonons( APDU apdu)
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;

	    if( DEBUG_MODE )
	    {
	    	len = apdu.getIncomingLength();
	    }
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);
//	    	len = secureChannel.CardpreprocessAPDU(apduBuffer);
	    	len = (short)((short) apduBuffer[ISO7816.OFFSET_LC] & 0xff);
	    	Util.arrayCopyNonAtomic(apduBuffer, (short)ISO7816.OFFSET_CDATA, OutputData, (short)0, len);
	    	len= secureChannel.CardDecrypt( OutputData, len);
	    	Util.arrayCopyNonAtomic(OutputData, (short)0, apduBuffer, (short)0, len);
	    	apdu.setOutgoingAndSend((short)0, len);
	    	return;
/*	    	if (!pin.isValidated())
	    	{
		        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//	    		secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    		return;
	    	}
*/	    }

		if(phononKeyIndex >= MAX_NUMBER_PHONONS)
		{
	        ISOException.throwIt(ISO7816.SW_FILE_FULL);
//			secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_FILE_FULL);
			return;
		}
/*	    if( SetReceiveList == false)  // not used in alpha
	    {
	        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//			secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			return;
	    }
*/
//        byte[] IncomingData = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
//        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short)0,len);

//      byte[] IncomingPhonon = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        Bertlv RecievePhononTLV = BertlvArray[0];;
        byte[] IncomingPhonon = OutputData;
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingPhonon, (short)0,len);
        RecievePhononTLV.LoadTag(IncomingPhonon);
        if( RecievePhononTLV.GetTag() != TLV_PHONON_TRANSFER_PACKET )
        {

        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//			secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
        short PhononCount = RecievePhononTLV.GetLength();
        PhononCount = (short)(PhononCount / 46);
        short Offset = 0;
        for( short i = 0; i < PhononCount; i++)
        {
			if(phononKeyIndex >= MAX_NUMBER_PHONONS)
			{
		        ISOException.throwIt(ISO7816.SW_FILE_FULL);
//				secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_FILE_FULL);
				return;
			}
			Bertlv PhononTLV = BertlvArray[1];

		    PhononTLV.LoadNextTag(RecievePhononTLV.GetData(), Offset);
		    Offset = PhononTLV.bertag.nextData;

		    Bertlv PhononECCTLV = BertlvArray[2];
		    PhononECCTLV.LoadTag( PhononTLV.GetData());

		    Bertlv PhononValueTLV = BertlvArray[3];
		    PhononValueTLV.LoadNextTag(PhononTLV.GetData(), PhononECCTLV.bertag.nextData);

		    Bertlv PhononTypeTLV = BertlvArray[4];
		    PhononTypeTLV.LoadNextTag(PhononTLV.GetData(), PhononValueTLV.bertag.nextData);

		    JCSystem.beginTransaction();
			short phononKeyPointer = phononKeyIndex;
			byte UsingDeletedSpot = 0;
			if( DeletedPhononIndex == 0)
			{
				PhononArray2[phononKeyPointer] = new Phonon2();
				phononKeyIndex++;
			}
			else
			{
				DeletedPhononIndex--;
				phononKeyPointer = DeletedPhononList[DeletedPhononIndex];
				UsingDeletedSpot = 1;
			}
			ECPrivateKey PrivateKey = (ECPrivateKey) PhononKey.getPrivate();

			PhononArray2[phononKeyPointer].PhononPrivateKeyLen = PhononECCTLV.GetLength();
			if( UsingDeletedSpot == 0 )
			{
				PhononArray2[phononKeyPointer].sPhononPrivateKey = new byte[PhononArray2[phononKeyPointer].PhononPrivateKeyLen];
			}
			Util.arrayCopyNonAtomic(PhononECCTLV.GetData(), (short)0, PhononArray2[phononKeyPointer].sPhononPrivateKey, (short)0, PhononArray2[phononKeyPointer].PhononPrivateKeyLen);
		    PrivateKey.setS(PhononArray2[phononKeyPointer].sPhononPrivateKey, (short)0, PhononArray2[phononKeyPointer].PhononPrivateKeyLen);
		    byte [] PublicKeystr = OutputData;

		    short PublicKeyLength = secp256k1.derivePublicKey(PrivateKey, PublicKeystr, (short)0);
		    ECPublicKey PublicKey = (ECPublicKey)PhononKey.getPublic();
		    PublicKey.setW(PublicKeystr, (short)0, PublicKeyLength);

			PhononArray2[phononKeyPointer].PhononPublicKeyLen = PublicKeyLength;
			if( UsingDeletedSpot == 0 )
			{
				PhononArray2[phononKeyPointer].sPhononPublicKey = new byte[PhononArray2[phononKeyPointer].PhononPublicKeyLen];
			}
			Util.arrayCopyNonAtomic(PublicKeystr, (short)0, PhononArray2[phononKeyPointer].sPhononPublicKey, (short)0, PhononArray2[phononKeyPointer].PhononPublicKeyLen);
		    PhononArray2[phononKeyPointer].CurrencyType = Util.getShort( PhononTypeTLV.GetData(), (short)0);

	         short vLen = PhononValueTLV.GetLength();
	         PhononArray2[phononKeyPointer].Value = new byte[vLen];
	         Util.arrayCopyNonAtomic(PhononValueTLV.GetData(), (short)0, PhononArray2[phononKeyPointer].Value, (short)0, vLen);

			// Check to make sure generated public key matches what was sent by SET_RECV_LIST
/* Removed for alpha
	         if(Util.arrayCompare(PublicKeystr, (short)0, SetReceiveListPubKey, (short)0, PublicKeyLength) != 0 )
	         {
			        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
//	 			secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
	        	 return;
	         }
*/
	         PhononArray2[phononKeyPointer].Status = PHONON_STATUS_INITIALIZED;

	         JCSystem.commitTransaction();
			phononKeyIndex++;
        }
//        if( DEBUG_MODE == false)
//        	secureChannel.respond( apdu, (short)0, ISO7816.SW_NO_ERROR);
//    	secureChannel.Cardrespond( apdu, (short)0, ISO7816.SW_NO_ERROR);
		return;
	}

	private void DestroyPhonon( APDU apdu )
	{
		byte [] apduBuffer = apdu.getBuffer();
		short len;
		if( DEBUG_MODE )
			len = apdu.getIncomingLength();
		else
		{
			len = secureChannel.preprocessAPDU(apduBuffer);
			if (!pin.isValidated())
			{
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
			}
		}
		byte [] IncomingData  = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short)0,len);
		if( len > 4)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_LENGTH);
	        return;
        }
        Bertlv berPhononIndex = BertlvArray[0];
        byte [] IncomingPhonon = IncomingData;

        berPhononIndex.LoadTag(IncomingPhonon);
        if( berPhononIndex.GetTag() != TLV_SET_PHONON_KEY_INDEX)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
         short PhononIndex = Util.getShort( berPhononIndex.GetData(), (short)0);

         if ( PhononIndex == 0)
         {
 			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
 			return;
          }
         PhononIndex--;
        if( PhononIndex >= phononKeyIndex)
         {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
         }
        if( PhononArray2[PhononIndex]== null ||  PhononArray2[PhononIndex].Status == PHONON_STATUS_DELETED )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
        }
        JCSystem.beginTransaction();
        Bertlv berPhononKey = BertlvArray[1];
        byte[] OutgoingData = OutputData;
        berPhononKey.BuildTLVStructure(TLV_PRIV_KEY, PhononArray2[PhononIndex].PhononPrivateKeyLen, PhononArray2[PhononIndex].sPhononPrivateKey, OutgoingData);
        PhononArray2[PhononIndex].Status = PHONON_STATUS_DELETED;
        PhononArray2[PhononIndex].CurrencyType = 0;

        DeletedPhononList[DeletedPhononIndex] = PhononIndex;
        DeletedPhononIndex++;
        JCSystem.commitTransaction();
        if( DEBUG_MODE == false)
        	secureChannel.respond(apdu,OutgoingData, berPhononKey.BuildLength, ISO7816.SW_NO_ERROR);
		return;
	}

	private void SetPhononDescriptor( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if( DEBUG_MODE)
	    	len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);

	    	if (!pin.isValidated())
	    	{
	    		secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    		return;
	    	}
	    }
        byte [] IncomingData = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short)0,len);
        if( len > 16 )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_LENGTH);
	        return;
        }

        Bertlv Phonon = BertlvArray[0];

        Phonon.LoadTag(IncomingData);
        if( Phonon.GetTag() != TLV_SET_PHONON_DESCRIPTOR )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
        byte [] ptrIndex = Phonon.GetData();
        Bertlv berPhononIndex = BertlvArray[1];
        berPhononIndex.LoadTag(ptrIndex);
        short PhononOffset =  berPhononIndex.bertag.nextData;
        if( berPhononIndex.GetTag() != TLV_SET_PHONON_KEY_INDEX)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
         short PhononIndex = Util.getShort( berPhononIndex.GetData(), (short)0);


         if ( PhononIndex == 0)
         {
 			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
 			return;
         }
         PhononIndex--;

        if( PhononIndex >= phononKeyIndex)
         {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
         }

        if( PhononArray2[PhononIndex]== null)
        {
 			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
         	return;

        }

        if( PhononArray2[PhononIndex].CurrencyType != 0x00)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FUNC_NOT_SUPPORTED);
			return;
        }

        Bertlv berPhononCurrency = BertlvArray[2];

         berPhononCurrency.LoadNextTag( ptrIndex, PhononOffset );
         PhononOffset = berPhononCurrency.bertag.nextData;

         if(berPhononCurrency.GetTag() != TLV_SET_PHONON_CURRENCY)
         {
 			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
 			return;
         }

         byte [] ptrTemp = berPhononCurrency.GetData();
         short CurrencyType = Util.getShort( ptrTemp, (short)0);
         if( CurrencyType == 0x00)
         {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_DATA_INVALID);
 			return;
         }
         JCSystem.beginTransaction();
         PhononArray2[PhononIndex].CurrencyType = CurrencyType;

         Bertlv berPhononValue = BertlvArray[3];

         berPhononValue.LoadNextTag( ptrIndex, PhononOffset);
         PhononOffset = berPhononValue.bertag.nextData;

         if(berPhononValue.GetTag() != TLV_SET_PHONON_VALUE)
         {
 			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
 			return;
         }
         short vLen = berPhononValue.GetLength();
         if( PhononArray2[PhononIndex].Value == null)
        	 PhononArray2[PhononIndex].Value = new byte[vLen];

         Util.arrayCopyNonAtomic(berPhononValue.GetData(), (short)0, PhononArray2[PhononIndex].Value, (short)0, vLen);
         JCSystem.commitTransaction();
         if( DEBUG_MODE == false)
        	 secureChannel.respond( apdu, (short)0, ISO7816.SW_NO_ERROR);
         return;
 	}


	private void GetPhononPublicKey( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if( DEBUG_MODE)
	    	len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);
	    	if (!pin.isValidated())
	    	{
	    		secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    		return;
	    	}
	    }
       byte [] IncomingData = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short)0,len);
        if( len > 4 )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_LENGTH);
	        return;
        }

        Bertlv berPhononIndex = BertlvArray[0];
        byte [] IncomingPhononIndex = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(IncomingData, (short)0, IncomingPhononIndex, (short)0,len);
       berPhononIndex.LoadTag(IncomingPhononIndex);
        if( berPhononIndex.GetTag() != TLV_PHONON_INDEX )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
        short PhononIndex = Util.getShort(berPhononIndex.GetData(), (short)0);
        if ( PhononIndex == 0)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
         }
        PhononIndex--;
        if( PhononIndex >= phononKeyIndex)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
        }
        if( PhononArray2[PhononIndex]== null )
		{
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
		}

        if( PhononArray2[PhononIndex].CurrencyType == (short)0)
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_INVALID);
			return;
        }
        if( PhononArray2[PhononIndex].Status != PHONON_STATUS_INITIALIZED )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_FILE_NOT_FOUND);
			return;
        }
        Bertlv berPhononKey = BertlvArray[1];

        byte [] OutgoingBuffer;
        if(DEBUG_MODE)
        	OutgoingBuffer = apduBuffer;
        else
        	OutgoingBuffer = OutputData;
	    berPhononKey.BuildTLVStructure(TLV_PUB_KEY, PhononArray2[PhononIndex].PhononPublicKeyLen, PhononArray2[PhononIndex].sPhononPublicKey, OutgoingBuffer);
	    if( DEBUG_MODE)
	    	apdu.setOutgoingAndSend((short) 0, (short)berPhononKey.BuildLength);
	    else
	    	secureChannel.respond( apdu,  OutgoingBuffer, berPhononKey.BuildLength, ISO7816.SW_NO_ERROR);
        return;
 	}


	private void ListPhonons( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    byte PhononListContinue = apduBuffer[ ISO7816.OFFSET_P1];
	    byte PhononFilter = apduBuffer[ ISO7816.OFFSET_P2];
	    short len;
	    if(DEBUG_MODE)
	    	len = apdu.getIncomingLength();
	    else
	    	len = secureChannel.preprocessAPDU(apduBuffer);

	    if( len == 0 && PhononListContinue == 0)
	    {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
	    }
	    if( DEBUG_MODE == false)
	    {
	    	if (!pin.isValidated())
	    	{
	    		secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    		return;
	    	}
	    }
	    if( PhononListContinue > 1 )
	    {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_INCORRECT_P1P2);
			return;
	    }

        byte [] IncomingData = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);

       Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, IncomingData, (short)0,len);

	    if( PhononListContinue == 0x00)
	    {
		    if( PhononFilter > LIST_FILTER_LAST)
		    {
				secureChannel.respond( apdu, (short)0, ISO7816.SW_INCORRECT_P1P2);
				return;
		    }
	        Bertlv PhononFilterTLV = BertlvArray[0];
	        byte [] IncomingPhonon = IncomingData;
	        PhononFilterTLV.LoadTag(IncomingPhonon);
	        if( PhononFilterTLV.GetTag() != TLV_PHONON_FILTER )
	        {
				secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
				return;
	        }
		    short Offset = PhononFilterTLV.FindTag(TLV_SET_PHONON_CURRENCY);
		    if( Offset == TLV_NOT_FOUND )
		    {
		    	// No Coin Type Specified
				secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
				return;
		    }
		    Bertlv PhononCoinTypeTLV = BertlvArray[1];
		    PhononCoinTypeTLV.LoadTagBase( PhononFilterTLV.bertag.data, Offset);
		    short PhononCoinType = Util.getShort(PhononCoinTypeTLV.bertag.data, (short)0);

		    byte [] PhononLessThanValue = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);

		    Util.arrayFillNonAtomic(PhononLessThanValue, (short)0, (short)4, (byte)0);
		    if( PhononFilter == LIST_FILTER_LESS_THAN || PhononFilter == LIST_FILTER_GT_AND_LT)
		    {
			    Offset = PhononFilterTLV.FindTag(TLV_PHONON_LESS_THAN);
			    if( Offset == TLV_NOT_FOUND )
			    {
			    	// No Coin Type Specified
					secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
					return;
			    }
			    Bertlv PhononLessThanTLV = BertlvArray[2];
			    PhononLessThanTLV.LoadTagBase( PhononFilterTLV.bertag.data, Offset);
			    Util.arrayCopyNonAtomic(PhononLessThanTLV.bertag.data, (short)0, PhononLessThanValue, (short)0, (short)4);
		    }
		    byte[] PhononGreaterThanValue = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);

		    Util.arrayFillNonAtomic(PhononGreaterThanValue, (short)0, (short)4, (byte)0);
		    if( PhononFilter == LIST_FILTER_GREATER_THAN || PhononFilter == LIST_FILTER_GT_AND_LT)
		    {
			    Offset = PhononFilterTLV.FindTag(TLV_PHONON_GREATER_THAN);
			    if( Offset == TLV_NOT_FOUND )
			    {
			    	// No Coin Type Specified
					secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
					return;
			    }
			    Bertlv PhononGreaterThanTLV = BertlvArray[3];
			    PhononGreaterThanTLV.LoadTagBase( PhononFilterTLV.bertag.data, Offset);
			    Util.arrayCopyNonAtomic(PhononGreaterThanTLV.bertag.data, (short)0, PhononGreaterThanValue, (short)0, (short)4);
		    }
		    PhononListCount = 0;
		    PhononListLastSent = 0;
		    switch( PhononFilter)
		    {
		    	case LIST_FILTER_ALL:
		    	{
		    		for( short i= 0; i< phononKeyIndex; i++)
		    		{
		    			if( PhononArray2[i] != null && PhononArray2[i].Status == PHONON_STATUS_INITIALIZED )
		    			{
			    			if( PhononCoinType == 0 || PhononCoinType == PhononArray2[i].CurrencyType )
			    			{
			    				PhononList[ PhononListCount] = i;
			    				PhononListCount++;
			    			}
		    			}
		    		}
		    		break;
		    	}
		    	case LIST_FILTER_LESS_THAN:
		    	{
		    		for( short i= 0; i< phononKeyIndex; i++)
		    		{
		    			if( PhononArray2[i] != null && PhononArray2[i].Status == PHONON_STATUS_INITIALIZED)
		    			{
			    			if( ( PhononCoinType == 0 && PhononArray2[i].CurrencyType != 0 ) || PhononCoinType == PhononArray2[i].CurrencyType )
			    			{
			    				if(Util.arrayCompare(PhononArray2[i].Value, (short)0, PhononLessThanValue, (short)0, (short)4) != 1 )
			    				{
			    					PhononList[ PhononListCount] = i;
			    					PhononListCount++;
			    				}
			    			}
		    			}
		    		}
		    		break;
		    	}
		    	case LIST_FILTER_GREATER_THAN:
		    	{
		    		for( short i= 0; i< phononKeyIndex; i++)
		    		{
		    			if( PhononArray2[i] != null && PhononArray2[i].Status == PHONON_STATUS_INITIALIZED)
		    			{
			    			if( ( PhononCoinType == 0 && PhononArray2[i].CurrencyType != 0 ) || PhononCoinType == PhononArray2[i].CurrencyType )
			    			{
			    				if(Util.arrayCompare(PhononArray2[i].Value, (short)0, PhononGreaterThanValue, (short)0, (short)4) != -1 )
			    				{
			    					PhononList[ PhononListCount] = i;
			    					PhononListCount++;
			    				}
			    			}
		    			}
		    		}
		    		break;
		    	}
		    	case LIST_FILTER_GT_AND_LT:
		    	{
		    		for( short i= 0; i< phononKeyIndex; i++)
		    		{
		    			if( PhononArray2[i] != null && PhononArray2[i].Status == PHONON_STATUS_INITIALIZED)
		    			{
			    			if( ( PhononCoinType == 0 && PhononArray2[i].CurrencyType != 0 )|| PhononCoinType == PhononArray2[i].CurrencyType )
			    			{
			    				if(Util.arrayCompare(PhononArray2[i].Value, (short)0, PhononLessThanValue, (short)0, (short)4) != 1 )
			    				{
				    				if(Util.arrayCompare(PhononArray2[i].Value, (short)0, PhononGreaterThanValue, (short)0, (short)4) != -1 )
				    				{
				    					PhononList[ PhononListCount] = i;
				    					PhononListCount++;
				    				}

			    				}
			    			}
		    			}
		    		}
		    		break;
		    	}
		    }
	    }

	    SendSelectPhononList( apdu,TLV_PHONON_COLLECTION);
	    return;
	}

	private void SendSelectPhononList( APDU apdu, byte tlvTag )
	{
	    byte[] apduBuffer = apdu.getBuffer();

//	    byte [] PhononCollection = OutputData2;
	    byte [] PhononCollection = OutputData;
	    short PhononCollectionOffset = 0;
	    short i,j;
		byte [] PhononTLVData = JCSystem.makeTransientByteArray((short)24, JCSystem.CLEAR_ON_DESELECT);;
		byte [] Blank = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		byte [] tlvtemp = JCSystem.makeTransientByteArray((short)24, JCSystem.CLEAR_ON_DESELECT);
		for( j = PhononListLastSent; j< PhononListCount; j++)
		{
			i = PhononList[ j ];
			short Offset = 0;

 			Bertlv berPhononValue = BertlvArray[0];
 			if( PhononArray2[i].CurrencyType != 0 )
  			{
 				berPhononValue.BuildTLVStructure(TLV_SET_PHONON_VALUE, (short)4, PhononArray2[i].Value, tlvtemp);
 			}
 			else
 			{
 				Util.arrayFillNonAtomic(Blank, (short)0, (short)4, (byte)0);
 				berPhononValue.BuildTLVStructure(TLV_SET_PHONON_VALUE, (short)4, Blank, tlvtemp);

 			}
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononValue.BuildLength);
			Offset += berPhononValue.BuildLength;

			Bertlv berPhononType = BertlvArray[1];
			berPhononType.BuildTLVStructure( TLV_SET_PHONON_CURRENCY, (short)2, PhononArray2[i].CurrencyType, tlvtemp );
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononType.BuildLength);
			Offset += berPhononType.BuildLength;

			Bertlv berPhononIndex = BertlvArray[2];
			berPhononIndex.BuildTLVStructure( TLV_SET_PHONON_KEY_INDEX, (short)2, (short)(i+1), tlvtemp );
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononIndex.BuildLength);
			Offset += berPhononIndex.BuildLength;

			Bertlv berPhonon = BertlvArray[3];
			berPhonon.BuildTLVStructure(TLV_SET_PHONON_DESCRIPTOR, Offset, PhononTLVData, tlvtemp );
			Util.arrayCopyNonAtomic(tlvtemp, (short) 0, PhononCollection, PhononCollectionOffset, berPhonon.BuildLength);
			PhononCollectionOffset += berPhonon.BuildLength;
			if( (short)(PhononCollectionOffset + berPhonon.BuildLength) > (short)(200))
				break;
		}
		Bertlv berPhononCollection = BertlvArray[4];
//		byte [] OutgoingBuffer = OutputData;
		byte [] OutgoingBuffer = apduBuffer;
		berPhononCollection.BuildTLVStructure(TLV_PHONON_COLLECTION, PhononCollectionOffset, PhononCollection, OutgoingBuffer);
 		short remaining = (short)ISO7816.SW_NO_ERROR;
	    if( j < PhononListCount )
	    {
	    	PhononListLastSent = (short)(j + 1);
	    	remaining = (short)((short)(PhononListCount - PhononListLastSent )+ (short)(ISO7816.SW_NO_ERROR));
	    }
	    if(DEBUG_MODE)
	    {
	    	Util.arrayCopyNonAtomic(OutgoingBuffer, (short)0, apduBuffer, (short)0, (short)(PhononCollectionOffset + 2));
	    	apdu.setOutgoingAndSend((short) 0, (short)(PhononCollectionOffset + 2));

	    }
	    else
	    	secureChannel.respond( apdu, OutgoingBuffer, (short)(PhononCollectionOffset + 2), remaining);
		return;
	}

	private void SendPhonons( APDU apdu)
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if( DEBUG_MODE)
	    	len = apdu.getIncomingLength();
	    else
	    {
	    	len = secureChannel.preprocessAPDU(apduBuffer);
//	    	len = secureChannel.CardpreprocessAPDU(apduBuffer);
	    	if (!pin.isValidated())
	    	{
	    		secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    		return;
	    	}
	    }

//	    byte[] IncomingData = apduBuffer;
	    byte PhononListContinue = apduBuffer[ ISO7816.OFFSET_P1];
	    if( PhononListContinue > 1 )
	    {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_INCORRECT_P1P2);
			return;
	    }

	    if( PhononListContinue == 0 )
	    {
	  	  	SendPhononListCount = 0;
	  	  	SendPhononListLastSent = 0;
	    	byte PhononRequest = apduBuffer[ ISO7816.OFFSET_P2];

	    	if( PhononRequest == 0 )
		    {
				secureChannel.respond( apdu, (short)0, ISO7816.SW_INCORRECT_P1P2);
				return;
		    }
	        Bertlv PhononListTLV = BertlvArray[0];
	        byte [] IncomingPhonon =OutputData;
	        Util.arrayCopyNonAtomic(apduBuffer, (short)ISO7816.OFFSET_CDATA, IncomingPhonon, (short)0, len);
	        PhononListTLV.LoadTag(IncomingPhonon);
	        if( PhononListTLV.GetTag() != TLV_PHONON_INDEX_COUNT )
	        {
				secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
				return;
	        }
	        SendPhononListCount = (short)(PhononListTLV.GetLength() / 2 );
	        short Offset = 0;
	        for( short i = 0; i < SendPhononListCount; i++)
	        {
	        	SendPhononList[ i ] = Util.getShort(PhononListTLV.GetData(), Offset);
	        	Offset += 2;
	        }
	    }
        SendPhononList( apdu, TLV_PHONON_TRANSFER_PACKET);
		return;
	}

	private void SendPhononList( APDU apdu, byte tlvTag )
	{

	    byte [] PhononCollection = JCSystem.makeTransientByteArray((short)200, JCSystem.CLEAR_ON_DESELECT);
		byte [] PhononTLVData = JCSystem.makeTransientByteArray((short)100, JCSystem.CLEAR_ON_DESELECT);
	    short PhononCollectionOffset = 0;
	    short i,j;
	    JCSystem.beginTransaction();
		for( j = SendPhononListLastSent; j< SendPhononListCount; j++)
		{
			Util.arrayFillNonAtomic(PhononTLVData, (short)0, (short)100, (byte)0x00);
			i = SendPhononList[ j ];
			i--;
//			byte [] PhononTLVData = JCSystem.makeTransientByteArray((short)100, JCSystem.CLEAR_ON_DESELECT);
			short Offset = 0;

			byte [] tlvtemp;

			Bertlv berPhononKey = BertlvArray[0];

		    tlvtemp = berPhononKey.BuildTLVStructure(TLV_PRIV_KEY, PhononArray2[i].PhononPrivateKeyLen, PhononArray2[i].sPhononPrivateKey);
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononKey.BuildLength);
			Offset += berPhononKey.BuildLength;

 			Bertlv berPhononValue = BertlvArray[1];
  			if( PhononArray2[i].CurrencyType != 0 )
  			{
 				tlvtemp = berPhononValue.BuildTLVStructure(TLV_SET_PHONON_VALUE, (short)4, PhononArray2[i].Value);
 			}
 			else
 			{
 				byte [] Blank = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
 				Util.arrayFillNonAtomic(Blank, (short)0, (short)4, (byte)0);
 				tlvtemp = berPhononValue.BuildTLVStructure(TLV_SET_PHONON_VALUE, (short)4, Blank);

 			}
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononValue.BuildLength);
			Offset += berPhononValue.BuildLength;

			Bertlv berPhononType = BertlvArray[2];
			tlvtemp = berPhononType.BuildTLVStructure( TLV_SET_PHONON_CURRENCY, (short)2, PhononArray2[i].CurrencyType );
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononType.BuildLength);
			Offset += berPhononType.BuildLength;
			PhononArray2[i].Status = PHONON_STATUS_SENT;

			Bertlv berPhonon = BertlvArray[3];
			tlvtemp = berPhonon.BuildTLVStructure(TLV_PHONON_PRIVATE_DESCRIPTOR, Offset, PhononTLVData );
			Util.arrayCopyNonAtomic(tlvtemp, (short) 0, PhononCollection, PhononCollectionOffset, berPhonon.BuildLength);
			PhononCollectionOffset += berPhonon.BuildLength;
			if( (short)(PhononCollectionOffset + berPhonon.BuildLength) > (short)(200))
				break;
		}
		Bertlv berPhononCollection = BertlvArray[4];
		byte[] OutgoingBuffer = OutputData;

		berPhononCollection.BuildTLVStructure(TLV_PHONON_TRANSFER_PACKET, PhononCollectionOffset, PhononCollection, OutgoingBuffer);
		short remaining = 0;
	    if( j < SendPhononListCount )
	    {
	    	SendPhononListLastSent = (short)(j + 1);
				//TODO: possibly SW_NO_ERROR is being double added here and will break things when the length exceeds one APDU
	    	remaining = (short)((short)(SendPhononListCount - SendPhononListLastSent )+ (short)(ISO7816.SW_NO_ERROR));
	    }
	    byte[] apduBuffer = apdu.getBuffer();
	    if( DEBUG_MODE)
	    {
	    	Util.arrayCopyNonAtomic(OutgoingBuffer, (short)0, apduBuffer, (short)0, (short)(PhononCollectionOffset + 2));
	    	apdu.setOutgoingAndSend((short) 0, (short)(PhononCollectionOffset + 2));
	    }
	    else
	    {
				//This stuff, what's going on
				//Try sending back a plaintext phononTransferPacket without encrypting
				//Plaintext version of the return packet is correct
				//Problem is somewhere in this encryption function
	    	short encryptlen = secureChannel.CardEncrypt( OutgoingBuffer,(short)(PhononCollectionOffset + 2));
	    	// byte [] CardAESCMAC = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
	    	// secureChannel.CalcCardAESMAC(OutgoingBuffer, encryptlen, CardAESCMAC);
	    	apduBuffer = apdu.getBuffer();
	    	// Util.arrayCopyNonAtomic(secureChannel.CardGetAESIV(), (short)0, apduBuffer, (short)0, (short)16);
	    	// Util.arrayCopyNonAtomic( CardAESCMAC, (short)0, apduBuffer, (short)16, (short)16);
	    	// Util.arrayCopyNonAtomic(OutgoingBuffer,  (short)0, apduBuffer, (short)32, (short)encryptlen);
				//Just copy card2card encrypted data into output data
				Util.arrayCopyNonAtomic(OutgoingBuffer, (short)0, apduBuffer, (short)0, encryptlen);
				secureChannel.respond( apdu, apduBuffer, encryptlen, (short)( ISO7816.SW_NO_ERROR + remaining));
	    }
	    JCSystem.commitTransaction();
		return;
	}

	private void SetTransactionsAsComplete( APDU apdu)
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    short len;
	    if( DEBUG_MODE)
	    	len = apdu.getIncomingLength();
	    else
	    {
		    len = secureChannel.preprocessAPDU(apduBuffer);
		    if (!pin.isValidated())
		    {
				secureChannel.respond( apdu, (short)0, ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				return;
			}
	    }

       Bertlv PhononListTLV = BertlvArray[0];
       byte [] IncomingList = apduBuffer;
       PhononListTLV.LoadTag(IncomingList);
        if( PhononListTLV.GetTag() != TLV_PHONON_INDEX_COUNT )
        {
			secureChannel.respond( apdu, (short)0, ISO7816.SW_WRONG_DATA);
			return;
        }
        SendPhononListCount = (short)(PhononListTLV.GetLength() / 2 );
       short Offset = 0;
        short Index;
        JCSystem.beginTransaction();
        for( short i = 0; i < SendPhononListCount; i++)
        {
        	Index = Util.getShort(PhononListTLV.GetData(), Offset);
        	Index--;
         	PhononArray2[ Index ].Status = PHONON_STATUS_DELETED;
        	Offset += 2;
        }
        JCSystem.commitTransaction();
        if(DEBUG_MODE == false)
        	secureChannel.respond(apdu, (short)0, ISO7816.SW_NO_ERROR);
		return;
	}


	private void selectApplet(APDU apdu) {
	    pin.reset();
	    secureChannel.reset();
	    secureChannel.updateSecureChannelCounter();

	    byte[] apduBuffer = apdu.getBuffer();

/*	    if(secureChannel.SECURE_CHANNEL_DEBUG == true)
	    {
	    	secureChannel.SetDebugKey();
	    }
*/	    short off = 0;

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

	    apduBuffer[lenoff] = (byte)(off - lenoff - 1);
	    apdu.setOutgoingAndSend((short) 0, off);
	  }

	 private void resetCurveParameters()
	 {
		    secp256k1.setCurveParameters(masterPublic);
		    secp256k1.setCurveParameters(masterPrivate);

		    secp256k1.setCurveParameters(parentPublicKey);
		    secp256k1.setCurveParameters(parentPrivateKey);

		    secp256k1.setCurveParameters(publicKey);
		    secp256k1.setCurveParameters(privateKey);

		    secp256k1.setCurveParameters(pinlessPublicKey);
		    secp256k1.setCurveParameters(pinlessPrivateKey);
	}

	private void processInit(APDU apdu)
	{
		    byte[] apduBuffer = apdu.getBuffer();
		    apdu.setIncomingAndReceive();

		    if (selectingApplet()) {
		      apduBuffer[0] = TLV_PUB_KEY;
		      apduBuffer[1] = (byte) secureChannel.copyPublicKey(apduBuffer, (short) 2);
		      apdu.setOutgoingAndSend((short) 0, (short)(apduBuffer[1] + 2));
		    }
		    else
		    if (apduBuffer[ISO7816.OFFSET_INS] == INS_INIT)
		    {
		      secureChannel.oneShotDecrypt(apduBuffer);

		      if ((apduBuffer[ISO7816.OFFSET_LC] != (byte)(PIN_LENGTH  + SecureChannel.SC_SECRET_LENGTH)) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, (short)(PIN_LENGTH )))
		      {
		        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		      }

		      JCSystem.beginTransaction();
		      secureChannel.initSecureChannel(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH ));

		      pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
		      pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);

		      JCSystem.commitTransaction();
			  secp256k1.setCurveParameters((ECKey) PhononKey.getPrivate());
			  secp256k1.setCurveParameters((ECKey) PhononKey.getPublic());
		    }
		    else
		    {
		      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		    }
	  }

	  /**
	   * Utility method to verify if all the bytes in the buffer between off (included) and off + len (excluded) are digits.
	   *
	   * @param buffer the buffer
	   * @param off the offset to begin checking
	   * @param len the length of the data
	   * @return whether all checked bytes are digits or not
	   */

	  private boolean allDigits(byte[] buffer, short off, short len)
	  {
		    while(len > 0) {
		      len--;

		      byte c = buffer[(short)(off+len)];

		      if (c < 0x30 || c > 0x39) {
		        return false;
		      }
		    }

		    return true;
	  }
	  private void unpair(APDU apdu)
	  {
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
	  private void verifyPIN(APDU apdu)
	  {
	    byte[] apduBuffer = apdu.getBuffer();
	    byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

	    if (!pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len))
	    {
	      ISOException.throwIt((short)((short) 0x63c0 | (short) pin.getTriesRemaining()));
	    }
	  }

	  /**
	   * Processes the CHANGE PIN command. Requires a secure channel to be already open and the user PIN to be verified. All
	   * PINs have a fixed format which is verified by this method.
	   *
	   * @param apdu the JCRE-owned APDU object.
	   */
	  private void changePIN(APDU apdu)
	  {
	    byte[] apduBuffer = apdu.getBuffer();
	    byte len = (byte) secureChannel.preprocessAPDU(apduBuffer);

	    if (!pin.isValidated()) {
	      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    }

	    switch(apduBuffer[ISO7816.OFFSET_P1]) {
	      case CHANGE_PIN_P1_USER_PIN:
	        changeUserPIN(apduBuffer, len);
	        break;
	      case CHANGE_PIN_P1_PAIRING_SECRET:
	        changePairingSecret(apduBuffer, len);
	        break;
	      default:
	        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
	        break;
	    }
	  }
	  /**
	   * Changes the user PIN. Called internally by CHANGE PIN
	   * @param apduBuffer the APDU buffer
	   * @param len the data length
	   */
	  private void changeUserPIN(byte[] apduBuffer, byte len)
	  {
	    if (!(len == PIN_LENGTH && allDigits(apduBuffer, ISO7816.OFFSET_CDATA, len))) {
	      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	    }

	    pin.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
	    pin.check(apduBuffer, ISO7816.OFFSET_CDATA, len);
	  }

	  /**
	   * Changes the pairing secret. Called internally by CHANGE PIN
	   * @param apduBuffer the APDU buffer
	   * @param len the data length
	   */
	  private void changePairingSecret(byte[] apduBuffer, byte len) {
	    if (len != SecureChannel.SC_SECRET_LENGTH) {
	      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	    }

	    secureChannel.updatePairingSecret(apduBuffer, ISO7816.OFFSET_CDATA);
	  }

}