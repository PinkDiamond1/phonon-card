package io.gridplus.phonon;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.ISO7816;

public class Bertlv {

    BerTag bertag = new BerTag();
    //byte [] NextTagData;
    short[] TagTable;
    short TagTableCount = 0;
    short BuildLength = 0;
//	BerTag bertag = JCSystem.makeTransientObjectArray(BerTag, JCSystem.CLEAR_ON_RESET);

    public Bertlv() {
        bertag.data = JCSystem.makeTransientByteArray((short) 250, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        //NextTagData = new byte[255];
        TagTable = JCSystem.makeTransientShortArray((short) 50, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);

    }

    public void Clean() {
        Util.arrayFillNonAtomic(bertag.data, (short) 0, (short) 250, (byte) 0x00);
        BuildLength = 0;
        TagTableCount = 0;

    }
    public short BuildTagTable( byte[] Indata, short StartOffset, short Length)
    {
        TagTableCount = 0;
        short Offset = StartOffset;
        short FinishOffset = (short)(StartOffset + Length);
        short tempLen;
        while( Offset < FinishOffset)
        {
            TagTable[TagTableCount]=Offset;
            Offset++;
            tempLen = (short)(Indata[Offset] & (short)0x00FF);
            Offset =(short)(tempLen + 1 + Offset);
            TagTableCount++;
        }
        return TagTableCount;
    }

    public short GetIndexDataOffset(short index) {
        return TagTable[index];
    }

    public void LoadTagFromTable(byte[] Indata, short index) {
        if (index > (short) (TagTableCount - 1))
            return;
        LoadTagBase(Indata, TagTable[index]);
    }

    public void LoadTag(byte[] Indata) {
        short Offset = 0;
        LoadTagBase(Indata, Offset);
    }

    public void LoadTagBase(byte[] Indata, short Offset) {
        bertag.tag = Indata[Offset++];
        final short firstLen = Indata[Offset++];
        switch (firstLen) {
            case (byte) 0x81:
                bertag.length = (short) (
                        (short) Indata[Offset] & (short) 0x00FF);
                Offset++;
                break;
            case (byte) 0x82:
                bertag.length = (short) (Indata[Offset] << 8);
                Offset++;
                short ntemp = Indata[Offset];
                bertag.length += ntemp;
                Offset++;
                break;
            default:
                if (firstLen > (byte) 0x7f) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    return;
                }
                bertag.length = firstLen;
                break;
        }
        if (bertag.length != 0) {
//			bertag.data = JCSystem.makeTransientByteArray((short)bertag.length, JCSystem.CLEAR_ON_DESELECT);
            Util.arrayCopyNonAtomic(Indata, Offset, bertag.data, (short) 0, bertag.length);
        } else
            bertag.data = null;
        bertag.nextData = (short) (bertag.length + Offset);
    }

    public byte GetTag() {
        return bertag.tag;
    }

    public short GetLength() {
        return bertag.length;
    }

    public byte[] GetData() {
        return bertag.data;
    }


    public void BuildTLVStructure(byte tag, short length, byte[] InData, byte[] OutData) {
        short Offset = 0;
        OutData[Offset++] = tag;
        OutData[Offset++] = (byte) length;
        Util.arrayCopyNonAtomic(InData, (short) 0, OutData, Offset, length);
        BuildLength = (short) (Offset + length);
    }


    public void BuildTLVStructure(byte tag, short length, byte[] InData, byte[] OutputData, short OutOffset) {
        short Offset = OutOffset;
        OutputData[Offset++] = tag;
        OutputData[Offset++] = (byte) length;
        Util.arrayCopyNonAtomic(InData, (short) 0, OutputData, Offset, length);
        BuildLength = (short) (Offset + length - OutOffset);
    }


    public void BuildTLVStructure(byte tag, short length, short InData, byte[] OutData, short OutOffset) {
        short Offset = OutOffset;
        OutData[Offset++] = tag;
        OutData[Offset++] = (byte) length;

        Util.setShort(OutData, Offset, InData);

        BuildLength = (short) (Offset + 2 - OutOffset);
    }

    public void BuildTLVStructure(byte tag, short length, byte InData, byte[] OutData, short OutOffset) {
        short Offset = OutOffset;
        OutData[Offset++] = tag;
        OutData[Offset++] = (byte) length;
        OutData[Offset++] = InData;

        BuildLength = (short) (Offset - OutOffset);
    }

}
