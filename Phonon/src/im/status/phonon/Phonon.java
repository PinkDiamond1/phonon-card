package im.status.phonon;
//import javacard.security.*;

public class Phonon {

    //	KeyPair		PhononKey;
    short		PhononPublicKeyLen;
    byte []		sPhononPublicKey;
    //	ECPublicKey	PhononPublicKey;
//	ECPrivateKey PhononPrivateKey;
    short		CurrencyType;
    byte []		Value;
    short		PhononPrivateKeyLen;
    byte []		sPhononPrivateKey;
    byte		Status;
}
