package io.gridplus.phonon;

public class Phonon {
    short PhononPrivateKeyLen;
    byte[] sPhononPrivateKey;
    short PhononPublicKeyLen;
    byte[] sPhononPublicKey;
    byte KeyCurveType;
    byte SchemaVersion;
    byte ExtendedSchemaVersion;
    short CurrencyType;
    byte ValueBase;
    byte ValueExponent;
    byte[] ExtendedSchema;
    short ExtendedSchemaLength;
    byte Status;
}
