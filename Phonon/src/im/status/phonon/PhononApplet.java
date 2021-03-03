/**
 * 
 */
package im.status.phonon;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;


/**
 * @author MikeZercher
 *
 */
public class PhononApplet extends Applet {
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new PhononApplet(bArray, bOffset, bLength);
	}
	  static final short APPLICATION_VERSION = (short) 0x0001;
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
//	  static final byte CHANGE_PIN_P1_PUK = 0x01;
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

	  private byte[] derivationOutput;
	  private OwnerPIN pin;

	  public static final short PHONON_KEY_LENGTH = 256;
	  public static final short MAX_NUMBER_PHONONS = 512;
	  
	  static final byte TLV_SET_PHONON_DESCRIPTOR	= (byte)0x50;
	  static final byte TLV_PHONON_COLLECTION		= (byte)0x52;
	  static final byte TLV_PHONON					= (byte)0x51;
	  static final byte TLV_PHONON_COLLECTION_COUNT = (byte)0x53;
	  
	  static final byte TLV_PHONON_FILTER			= (byte)0x60;
	  static final byte	TLV_SET_PHONON_KEY_INDEX 	= (byte)0x41;
	  static final byte TLV_SET_PHONON_CURRENCY		= (byte)0x81;
	  static final byte TLV_SET_PHONON_VALUE		= (byte)0x83;
	  static final byte TLV_PHONON_LESS_THAN		= (byte)0x84;
	  static final byte TLV_PHONON_GREATER_THAN		= (byte)0x85;
	  
	  static final byte LIST_FILTER_ALL				= (byte) 0x00;
	  static final byte LIST_FILTER_LESS_THAN		= (byte) 0x01;
	  static final byte LIST_FILTER_GREATER_THAN	= (byte) 0x02;
	  static final byte LIST_FILTER_GT_AND_LT		= (byte) 0x03;
	  static final byte LIST_FILTER_LAST			= (byte) 0x03;
	  
	  static final short TLV_NOT_FOUND				= (short)0xffff;
	  
//	  private KeyPair[] phononKeyPair;
	  private ECPublicKey phononPublicKey;
	  private ECPrivateKey phononPrivateKey;
	  private byte phononKeyIndex = 0;

	  private Phonon[]	PhononArray;
	  private short[]	PhononList;
	  
	  private short		PhononListCount;
	  private short		PhononListLastSent;
	  
//	  private byte[]	PhononValueArray;
//	  private short[]	PhononCurrencyTypeArray;
	  
	  public PhononApplet(byte[] bArray, short bOffset, byte bLength) 
	  {
		    crypto = new Crypto();
		    secp256k1 = new SECP256k1(crypto);
		    secureChannel = new SecureChannel(PAIRING_MAX_CLIENT_COUNT, crypto, secp256k1);

		    uid = new byte[UID_LENGTH];
		    crypto.random.generateData(uid, (short) 0, UID_LENGTH);
		    
		    savedData = new byte[SAVED_DATA_SIZE];

		    masterSeed = new byte[BIP39_SEED_SIZE];
		    masterSeedStatus = MASTERSEED_EMPTY;
//		    phononKeyPair = new KeyPair[512];
		    PhononArray = new Phonon[ MAX_NUMBER_PHONONS ];
		    PhononList = new short[ MAX_NUMBER_PHONONS ];
		    PhononListCount = 0;
		    PhononListLastSent = 0;
		    
//		    PhononValueArray = new byte[512*4];
//		    PhononCurrencyTypeArray = new short[512];


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

		    derivationOutput = JCSystem.makeTransientByteArray((short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE), JCSystem.CLEAR_ON_RESET);

		    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
		  }
	
	public void process(APDU apdu) throws ISOException
	{
		// Good practice: Return 9000 on SELECT
		byte[] buf = apdu.getBuffer();
		if((buf[ISO7816.OFFSET_INS] != INS_CREATE_PHONON  )
				&& (buf[ISO7816.OFFSET_INS] != INS_LIST_PHONONS )
				&& (buf[ISO7816.OFFSET_INS] != INS_DESTROY_PHONON )
				&& (buf[ISO7816.OFFSET_INS] != INS_GET_PHONON_PUB_KEY )
			&& 	(buf[ISO7816.OFFSET_INS] != INS_SET_PHONON_DESCRIPTOR)	)
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

	private void createPhonon( APDU apdu)
	{
		if(phononKeyIndex > MAX_NUMBER_PHONONS)
		{
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
			return;
		}
		if( PhononArray[phononKeyIndex] != null)
		{
          	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
		}
		PhononArray[phononKeyIndex] = new Phonon();
	   PhononArray[phononKeyIndex].PhononKey = new KeyPair(KeyPair.ALG_EC_FP, PHONON_KEY_LENGTH);
	   secp256k1.setCurveParameters((ECKey) PhononArray[phononKeyIndex].PhononKey.getPrivate());
	   secp256k1.setCurveParameters((ECKey) PhononArray[phononKeyIndex].PhononKey.getPublic());
	   PhononArray[phononKeyIndex].PhononKey.genKeyPair();

	    byte[] apduBuffer = apdu.getBuffer();

	    short off = 0;

	    apduBuffer[off++] = TLV_PHONON_KEY;
	    
	    off++;
	    apduBuffer[off++] = TLV_PHONON_INDEX;
	    apduBuffer[off++] = 0x02;
	    Util.setShort(apduBuffer, off, (short)(phononKeyIndex + 1));
	    off += 2;
	    
	    apduBuffer[off++] = TLV_PUB_KEY;
	    short lenoff = off++;
	    ECPublicKey pk = (ECPublicKey)PhononArray[phononKeyIndex].PhononKey.getPublic();
	    
	    short keyLength = pk.getW(apduBuffer, off);
	    apduBuffer[lenoff] = (byte) keyLength;
	    off += keyLength;
	    apduBuffer[ 1 ] = (byte)(off - 1);
	    apdu.setOutgoingAndSend((short) 0, off);
	    phononKeyIndex++;
	}
	
	private void DestroyPhonon( APDU apdu )
	{
		byte [] apduBuffer = apdu.getBuffer();
		byte bLC = apduBuffer[ISO7816.OFFSET_LC];
		if( bLC > 4)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        return;
        }
        Bertlv berPhononIndex = new Bertlv();
        byte [] IncomingPhonon = new byte[apdu.getIncomingLength()];
        Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), IncomingPhonon, (short)0,apdu.getIncomingLength());
        berPhononIndex.LoadTag(IncomingPhonon);
        if( berPhononIndex.GetTag() != TLV_SET_PHONON_KEY_INDEX)
        {
           	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
         short PhononIndex = Util.getShort( berPhononIndex.GetData(), (short)0);
        
         if ( PhononIndex == 0)
         {
          	ISOException.throwIt(ISO7816.SW_FILE_INVALID);        	    	 
          }
         PhononIndex--;
        if( PhononIndex >= phononKeyIndex)
         {
         	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
         	    	 
         }
        if( PhononArray[PhononIndex]== null)
        {
         	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
         	    	 
        }
        Bertlv berPhononKey = new Bertlv();
        ECPrivateKey pk = (ECPrivateKey)PhononArray[PhononIndex].PhononKey.getPrivate();
	    
	    byte[] tempbuffer = new byte[255];
	    
	    short keyLength = pk.getS(tempbuffer, (short)0);
       
        berPhononKey.BuildTLVStructure(TLV_PRIV_KEY, keyLength, tempbuffer, apduBuffer);
        PhononArray[PhononIndex] = null;
 /*       phononKeyIndex--;
        for( short i = PhononIndex; i < phononKeyIndex; i++)
        	PhononArray[i]=PhononArray[+1];
*/        
        JCSystem.requestObjectDeletion();
	    apdu.setOutgoingAndSend((short) 0, (short)berPhononKey.BuildLength);
		return;
	}

	private void SetPhononDescriptor( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
        byte bLC = apduBuffer[ISO7816.OFFSET_LC];
        if( bLC > 16 )
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        return;
        }
        
        Bertlv Phonon = new Bertlv();
        byte [] IncomingPhonon = new byte[apdu.getIncomingLength()];
        Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), IncomingPhonon, (short)0,apdu.getIncomingLength());
        Phonon.LoadTag(IncomingPhonon);
        if( Phonon.GetTag() != TLV_SET_PHONON_DESCRIPTOR )
        {
        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        byte [] ptrIndex = Phonon.GetData();
        Bertlv berPhononIndex = new Bertlv();
        berPhononIndex.LoadTag(ptrIndex);
        short PhononOffset =  berPhononIndex.bertag.nextData;
        if( berPhononIndex.GetTag() != TLV_SET_PHONON_KEY_INDEX)
        {
           	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
         short PhononIndex = Util.getShort( berPhononIndex.GetData(), (short)0);
        
         if( PhononArray[PhononIndex]== null)
         {
           	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
           	    	 
         }
        	
         if ( PhononIndex == 0)
         {
          	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
          	    	 
          }
         PhononIndex--;
        if( PhononIndex >= phononKeyIndex)
         {
         	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
         	    	 
         }
        if( PhononArray[PhononIndex].CurrencyType != 0x00)
        {
        	ISOException.throwIt( ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        
         Bertlv berPhononCurrency = new Bertlv();
         ptrIndex = Phonon.GetNextData(PhononOffset );
         PhononOffset += berPhononCurrency.bertag.nextData;
         berPhononCurrency.LoadTag( ptrIndex );
         PhononOffset += berPhononCurrency.bertag.nextData;
         
         if(berPhononCurrency.GetTag() != TLV_SET_PHONON_CURRENCY)
         {
          	ISOException.throwIt(ISO7816.SW_FILE_INVALID);     	    	 
         }
        
         byte [] ptrTemp = berPhononCurrency.GetData();
         short CurrencyType = Util.getShort( ptrTemp, (short)0);
         if( CurrencyType == 0x00)
         {
         	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
         }
         PhononArray[PhononIndex].CurrencyType = CurrencyType;
         
         Bertlv berPhononValue = new Bertlv();
         ptrIndex = Phonon.GetNextData(PhononOffset );
         berPhononValue.LoadTag( ptrIndex);
         PhononOffset += berPhononValue.bertag.nextData;
         if(berPhononValue.GetTag() != TLV_SET_PHONON_VALUE)
         {
          	ISOException.throwIt(ISO7816.SW_FILE_INVALID);     	    	 
         }
         short vLen = berPhononValue.GetLength();
         PhononArray[PhononIndex].Value = new byte[vLen];
         Util.arrayCopyNonAtomic(berPhononValue.GetData(), (short)0, PhononArray[PhononIndex].Value, (short)0, vLen);
         return;
 	}
	
	private void GetPhononPublicKey( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
        byte bLC = apduBuffer[ISO7816.OFFSET_LC];
        if( bLC > 4 )
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        return;
        }
        
        Bertlv berPhononIndex = new Bertlv();
        byte [] IncomingPhononIndex = new byte[apdu.getIncomingLength()];
        Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), IncomingPhononIndex, (short)0,apdu.getIncomingLength());
        berPhononIndex.LoadTag(IncomingPhononIndex);
        if( berPhononIndex.GetTag() != TLV_PHONON_INDEX )
        {
        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short PhononIndex = Util.getShort(berPhononIndex.GetData(), (short)0);
        if ( PhononIndex == 0)
        {
         	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
         	    	 
         }
        PhononIndex--;
        if( PhononIndex >= phononKeyIndex)
        {
        	ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        	    	 
        }
        if( PhononArray[PhononIndex]== null )
		{
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			    	 
		}

        if( PhononArray[PhononIndex].CurrencyType == (short)0)
        {
          	ISOException.throwIt(ISO7816.SW_FILE_INVALID);     	    	 
   	
        }
        Bertlv berPhononKey = new Bertlv();
	    ECPublicKey pk = (ECPublicKey)PhononArray[PhononIndex].PhononKey.getPublic();
	    
	    byte[] tempbuffer = new byte[255];
	    
	    short keyLength = pk.getW(tempbuffer, (short)0);
       
        berPhononKey.BuildTLVStructure(TLV_PUB_KEY, keyLength, tempbuffer, apduBuffer);
	    apdu.setOutgoingAndSend((short) 0, (short)berPhononKey.BuildLength);
        return;
 	}

	private void ListPhonons( APDU apdu )
	{
	    byte[] apduBuffer = apdu.getBuffer();
	    byte PhononListContinue = apduBuffer[ ISO7816.OFFSET_P1];
	    if( PhononListContinue > 1 )
	    {
	    	ISOException.throwIt( ISO7816.SW_INCORRECT_P1P2);
	    }

	    if( PhononListContinue == 0x00)
	    {
		    byte PhononFilter = apduBuffer[ ISO7816.OFFSET_P2];
		    if( PhononFilter > LIST_FILTER_LAST)
		    {
		    	ISOException.throwIt( ISO7816.SW_INCORRECT_P1P2);
		    }
		    
	        Bertlv PhononFilterTLV = new Bertlv();
	        byte [] IncomingPhonon = new byte[apdu.getIncomingLength()];
	        Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), IncomingPhonon, (short)0,apdu.getIncomingLength());
	        PhononFilterTLV.LoadTag(IncomingPhonon);
	        if( PhononFilterTLV.GetTag() != TLV_PHONON_FILTER )
	        {
	        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);
	        }
		    short Offset = PhononFilterTLV.FindTag(TLV_SET_PHONON_CURRENCY);
		    if( Offset == TLV_NOT_FOUND )
		    {
		    	// No Coin Type Specified
	        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);  	
		    }
		    Bertlv PhononCoinTypeTLV = new Bertlv();
		    PhononCoinTypeTLV.LoadTagBase( PhononFilterTLV.bertag.data, Offset);
		    short PhononCoinType = Util.getShort(PhononCoinTypeTLV.bertag.data, (short)0);
		    
		    byte [] PhononLessThanValue = new byte[4];
		    
		    Util.arrayFillNonAtomic(PhononLessThanValue, (short)0, (short)4, (byte)0);
		    if( PhononFilter == LIST_FILTER_LESS_THAN || PhononFilter == LIST_FILTER_GT_AND_LT)
		    {
			    Offset = PhononFilterTLV.FindTag(TLV_PHONON_LESS_THAN);
			    if( Offset == TLV_NOT_FOUND )
			    {
			    	// No Coin Type Specified
		        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);  	
			    }
			    Bertlv PhononLessThanTLV = new Bertlv();
			    PhononLessThanTLV.LoadTagBase( PhononFilterTLV.bertag.data, Offset);
			    Util.arrayCopyNonAtomic(PhononLessThanTLV.bertag.data, (short)0, PhononLessThanValue, (short)0, (short)4);
		    }
		    byte [] PhononGreaterThanValue = new byte[4];
		    
		    Util.arrayFillNonAtomic(PhononGreaterThanValue, (short)0, (short)4, (byte)0);
		    if( PhononFilter == LIST_FILTER_GREATER_THAN || PhononFilter == LIST_FILTER_GT_AND_LT)
		    {
			    Offset = PhononFilterTLV.FindTag(TLV_PHONON_GREATER_THAN);
			    if( Offset == TLV_NOT_FOUND )
			    {
			    	// No Coin Type Specified
		        	ISOException.throwIt(ISO7816.SW_WRONG_DATA);  	
			    }
			    Bertlv PhononGreaterThanTLV = new Bertlv();
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
		    			if( PhononArray[i] != null)
		    			{
			    			if( PhononCoinType == 0 || PhononCoinType == PhononArray[i].CurrencyType )
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
		    			if( PhononArray[i] != null)
		    			{
			    			if( PhononCoinType == 0 || PhononCoinType == PhononArray[i].CurrencyType )
			    			{
			    				if(Util.arrayCompare(PhononArray[i].Value, (short)0, PhononLessThanValue, (short)0, (short)4) != 1 )
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
		    			if( PhononArray[i] != null)
		    			{
			    			if( PhononCoinType == 0 || PhononCoinType == PhononArray[i].CurrencyType )
			    			{
			    				if(Util.arrayCompare(PhononArray[i].Value, (short)0, PhononGreaterThanValue, (short)0, (short)4) != -1 )
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
		    			if( PhononArray[i] != null)
		    			{
			    			if( PhononCoinType == 0 || PhononCoinType == PhononArray[i].CurrencyType )
			    			{
			    				if(Util.arrayCompare(PhononArray[i].Value, (short)0, PhononLessThanValue, (short)0, (short)4) != 1 )
			    				{
				    				if(Util.arrayCompare(PhononArray[i].Value, (short)0, PhononGreaterThanValue, (short)0, (short)4) != -1 )
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

	    byte [] PhononCollection = new byte[ 250];
	    short PhononCollectionOffset = 0;
	    short i,j;
		for( j = PhononListLastSent; j< PhononListCount; j++)
		{
			i = PhononList[ j ];
			byte [] PhononTLVData = new byte[24];
			short Offset = 0;
			
 			Bertlv berPhononValue = new Bertlv();
			byte [] tlvtemp = berPhononValue.BuildTLVStructure(TLV_SET_PHONON_VALUE, (short)4, PhononArray[i].Value);
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononValue.BuildLength);
			Offset += berPhononValue.BuildLength;
			
			Bertlv berPhononType = new Bertlv();
			tlvtemp = berPhononType.BuildTLVStructure( TLV_SET_PHONON_CURRENCY, (short)2, PhononArray[i].CurrencyType );
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononType.BuildLength);
			Offset += berPhononType.BuildLength;
			
			Bertlv berPhononIndex = new Bertlv();
			tlvtemp = berPhononIndex.BuildTLVStructure( TLV_SET_PHONON_KEY_INDEX, (short)2, (short)(i+1) );
			Util.arrayCopyNonAtomic(tlvtemp, (short)0, PhononTLVData, Offset, berPhononIndex.BuildLength);
			Offset += berPhononIndex.BuildLength;
			
			Bertlv berPhonon = new Bertlv();
			tlvtemp = berPhonon.BuildTLVStructure(TLV_PHONON, Offset, PhononTLVData );
			Util.arrayCopyNonAtomic(tlvtemp, (short) 0, PhononCollection, PhononCollectionOffset, berPhonon.BuildLength);
			PhononCollectionOffset += berPhonon.BuildLength;
			if( (short)(PhononCollectionOffset + berPhonon.BuildLength) > (short)(250))
				break;
		}
		Bertlv berPhononCollection = new Bertlv();
		berPhononCollection.BuildTLVStructure(TLV_PHONON_COLLECTION, PhononCollectionOffset, PhononCollection, apduBuffer);
	    apdu.setOutgoingAndSend((short) 0, (short)(PhononCollectionOffset + 2));
	    if( j < PhononListCount )
	    {
	    	PhononListLastSent = (short)(j + 1);
	    	short remaining = (short)((short)(PhononListCount - PhononListLastSent )+ (short)(ISO7816.SW_NO_ERROR));
	    	ISOException.throwIt( remaining );
	    }
		return;
	
	}
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
		      
		      byte bLC = apduBuffer[ISO7816.OFFSET_LC];

//		      if ((apduBuffer[ISO7816.OFFSET_LC] != (byte)(PIN_LENGTH + PUK_LENGTH + SecureChannel.SC_SECRET_LENGTH)) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, (short)(PIN_LENGTH + PUK_LENGTH))) 
		      if ((apduBuffer[ISO7816.OFFSET_LC] != (byte)(PIN_LENGTH  + SecureChannel.SC_SECRET_LENGTH)) || !allDigits(apduBuffer, ISO7816.OFFSET_CDATA, (short)(PIN_LENGTH ))) 
		      {
		        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		      }

		      JCSystem.beginTransaction();
		      secureChannel.initSecureChannel(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH ));

		      pin = new OwnerPIN(PIN_MAX_RETRIES, PIN_LENGTH);
		      pin.update(apduBuffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);

//		      puk = new OwnerPIN(PUK_MAX_RETRIES, PUK_LENGTH);
//		      puk.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + PIN_LENGTH), PUK_LENGTH);

		      JCSystem.commitTransaction();
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