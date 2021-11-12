package io.gridplus.phonon;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.framework.ISO7816;

public class Bertlv {
	
	BerTag bertag = new BerTag();
	byte [] NextTagData;
	short [] TagTable;
	short TagTableCount = 0;
	short BuildLength = 0;
//	BerTag bertag = JCSystem.makeTransientObjectArray(BerTag, JCSystem.CLEAR_ON_RESET);
	
	public Bertlv()
	{
		bertag.data = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT); 
		NextTagData = new byte[255];
		TagTable = JCSystem.makeTransientShortArray((short)50, JCSystem.CLEAR_ON_DESELECT );
		
	}
	public void Clean()
	{/*
		Util.arrayFillNonAtomic(bertag.data, (short)0, (short)255, (byte)0x00);
		BuildLength = 0;
		TagTableCount=0;
		return;
		*/
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
		};
		return TagTableCount;
	}
	
	public short GetIndexDataOffset( short index )
	{
		return TagTable[index];
	}
	
	public short LoadTagFromTable( byte[]Indata, short index)
	{
		if( index > (short)(TagTableCount - 1) )
			return 0;
		return LoadNextTag( Indata, TagTable[index]);
	}
	
	public boolean LoadNextTag( Bertlv NextTag)
	{
		if( bertag.length >= bertag.nextData)
			return false;
	
		NextTag.LoadTagBase(bertag.data, bertag.nextData);
		bertag.nextData += NextTag.bertag.nextData;
		return true;
	}
	
	public short LoadNextTag( byte[] Indata, short Offset)
	{
		return LoadTagBase( Indata, Offset);
		
	}
	
	public short LoadTag(byte [] Indata)
	{
		short Offset = 0;
		return LoadTagBase( Indata, Offset);
	}
	
	public short FindTag( byte Tag)
	{
		short Length = (short)bertag.length;
		for(short i=0; i < Length;i++ )
		{
			if( bertag.data[ i ] == Tag)
				return i;
			i++;
			final byte firstLen = bertag.data[i++];
			short DataLen = 0;
/*			switch (firstLen) {
			case (byte)0x81:
				DataLen = (short)(
				    (short)bertag.data[i] & (short)0x00FF);
				i++;
				break;
			case (byte)0x82:
				DataLen = (short)(bertag.data[i]<<8);
				i++;
				short ntemp = (short)bertag.data[i];
				DataLen += ntemp;
				i ++;
				break;
			default:
				if (firstLen > (byte)0x7f) {
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
					return (0);
				}
*/				DataLen = (short)firstLen;
//				break;
//			}
			if( DataLen != 0 )
			{
				i = (short)(i + DataLen - 1);
			}			
		}
		return (short)0xffff;
	}
		
	public short LoadTagBase( byte [] Indata, short Offset)
	{
		bertag.tag = Indata[Offset++];
		final short firstLen = Indata[Offset++];
		switch (firstLen) {
		case (byte)0x81:
			bertag.length = (short)(
			    (short)Indata[Offset] & (short)0x00FF);
			Offset++;
			break;
		case (byte)0x82:
			bertag.length = (short)(Indata[Offset]<<8);
			Offset++;
			short ntemp = (short)Indata[Offset];
			bertag.length += ntemp;
			Offset ++;
			break;
		default:
			if (firstLen > (byte)0x7f) {
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				return (0);
			}
			bertag.length = (short)firstLen;
			break;
		}
		if( bertag.length != 0 )
		{
//			bertag.data = JCSystem.makeTransientByteArray((short)bertag.length, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayCopyNonAtomic(Indata, (short)Offset, bertag.data, (short)0, bertag.length);
		}
		else
			bertag.data =  null;
		bertag.nextData = (short)(bertag.length + Offset);
 		return bertag.length;
	}
	
	public byte GetTag()
	{
		return bertag.tag;
	}
	
	public short GetLength()
	{
		return bertag.length;
	}
	
	public byte [] GetData()
	{
		return bertag.data;
	}
	
	public byte [] GetNextData( byte [] InData, short Offset)
	{	
/*		byte [] NextTagData = JCSystem.makeTransientByteArray((short)((bertag.length)- Offset), JCSystem.CLEAR_ON_DESELECT );
		Util.arrayCopyNonAtomic( bertag.data, Offset, NextTagData, (short)0, (short)( bertag.length - Offset ));
		bertag.nextData = (short)(Offset + bertag.length);
		return NextTagData;
*/
//		byte [] NextTagData = JCSystem.makeTransientByteArray((short)((bertag.length)- bertag.nextData), JCSystem.CLEAR_ON_DESELECT );
		Util.arrayCopyNonAtomic( InData, Offset, NextTagData, (short)0, (short)( bertag.length - bertag.nextData ));
		bertag.nextData = (short)(bertag.nextData + bertag.length);
		return NextTagData;
	}

	public byte [] BuildTLVStructure( byte tag, short length, byte [] Data)
	{
		short totallength = (short) ((short)length + (short)2);
		if( length > 255 ) totallength = (short)(totallength+2);
		byte [] TLVString = JCSystem.makeTransientByteArray(totallength, JCSystem.CLEAR_ON_DESELECT );
		short Offset = 0;
		TLVString[ Offset++ ] = tag;
		if( length > 255)
		{
			TLVString[ Offset++ ] = (byte)0x82;
			Util.setShort(TLVString, Offset, length);
			Offset = (short)(Offset+2);
		}
		else
		{
//			TLVString[ Offset++] = (byte)0x81;
			TLVString[ Offset++] = (byte)length;
		}
		Util.arrayCopyNonAtomic(Data, (short)0, TLVString, Offset, length);
		BuildLength = (short)(Offset + length);
		return TLVString;
	}
	public byte [] BuildTLVStructure( byte tag, short length, short InData )
	{
		short totallength = (short) ((short)2 + (short)2);
		if( length > 255 ) totallength = (short)(totallength+2);
		byte [] TLVString = JCSystem.makeTransientByteArray(totallength, JCSystem.CLEAR_ON_DESELECT );
		short Offset = 0;
		TLVString[ Offset++ ] = tag;
		TLVString[ Offset++] = (byte)length;

		Util.setShort( TLVString,  Offset,  InData);
		
		BuildLength = (short)(Offset + 2);
		return TLVString;
	}

	public byte [] BuildTLVStructure( short tag, short length, byte [] Data)
	{
		short totallength = (short) ((short)length + (short)3);
		if( length > 255 ) totallength = (short)(totallength+2);
		byte [] TLVString = JCSystem.makeTransientByteArray(totallength, JCSystem.CLEAR_ON_DESELECT );
		short Offset = 0;
		Util.setShort(TLVString, Offset, tag);
		Offset = (short)(Offset+2);
		if( length > 255)
		{
			TLVString[ Offset++ ] = (byte)0x82;
			Util.setShort(TLVString, Offset, length);
			Offset+=2;
		}
		else
		{
//			TLVString[ Offset++] = (byte)0x81;
			TLVString[ Offset++] = (byte)length;
		}
		Util.arrayCopyNonAtomic(Data, (short)0, TLVString, Offset, length);
		BuildLength = (short)(Offset + length);
		return TLVString;
	}

	public byte [] BuildTLVStructure( short tag, short length, short InData)
	{
		short totallength = (short) ((short)length + (short)3);
		if( length > 255 ) totallength = (short)(totallength+2);
		byte [] TLVString = JCSystem.makeTransientByteArray(totallength, JCSystem.CLEAR_ON_DESELECT );
		short Offset = 0;
		Util.setShort(TLVString, Offset, tag);
		Offset = (short)(Offset+2);
		Util.setShort( TLVString,  Offset,  length);
		Offset = (short)(Offset+2);

		Util.setShort( TLVString,  Offset,  InData);
		
		BuildLength = (short)(Offset + 2);
		return TLVString;
	}

	public byte [] BuildTLVStructure( byte tag, short length, byte [] InData, byte [] OutData)
	{
		short totallength = (short) ((short)length + (short)2);
		if( length > 255 ) totallength = (short)(totallength+2);
		short Offset = 0;
		OutData[ Offset++ ] = tag;
		if( length > 255)
		{
			OutData[ Offset++ ] = (byte)0x82;
			Util.setShort(OutData, Offset, length);
			Offset = (short)(Offset+2);
		}
		else
		{
			OutData[ Offset++] = (byte)length;
		}
		Util.arrayCopyNonAtomic(InData, (short)0, OutData, Offset, length);
		BuildLength = (short)(Offset + length);
		return OutData;
	}

	
	public byte [] BuildTLVStructure( short tag, short length, byte [] InData, byte [] OutputData)
	{
		short totallength = (short) ((short)length + (short)3);
		if( length > 255 ) totallength = (short)(totallength+2);
		short Offset = 0;
		Util.setShort(OutputData, Offset, tag);
		Offset = (short)(Offset+2);
		if( length > 255)
		{
			OutputData[ Offset++ ] = (byte)0x82;
			Util.setShort(OutputData, Offset, length);
			Offset+=2;
		}
		else
		{
			OutputData[ Offset++] = (byte)length;
		}
		Util.arrayCopyNonAtomic(InData, (short)0, OutputData, Offset, length);
		BuildLength = (short)(Offset + length);
		return OutputData;
	}

	public byte [] BuildTLVStructure( byte tag, short length, byte [] InData, byte [] OutputData, short OutOffset)
	{
		short totallength = (short) ((short)length + (short)2);
		if( length > 255 ) totallength = (short)(totallength+2);
		short Offset = OutOffset;
//		Util.setShort(OutputData, Offset, tag);
		OutputData[ Offset++] = tag;
		if( length > 255)
		{
			OutputData[ Offset++ ] = (byte)0x82;
			Util.setShort(OutputData, Offset, length);
			Offset+=2;
		}
		else
		{
			OutputData[ Offset++] = (byte)length;
		}
		Util.arrayCopyNonAtomic(InData, (short)0, OutputData, Offset, length);
		BuildLength = (short)(Offset + length - OutOffset);
		return OutputData;
	}

	public byte [] BuildTLVStructure( byte tag, short length, short InData, byte [] OutData)
	{
		short totallength = (short) ((short)2 + (short)2);
		if( length > 255 ) totallength = (short)(totallength+2);
		short Offset = 0;
		OutData[ Offset++ ] = tag;
		OutData[ Offset++] = (byte)length;

		Util.setShort( OutData,  Offset,  InData);
		
		BuildLength = (short)(Offset + 2);
		return OutData;
	}

	
	public byte [] BuildTLVStructure( byte tag, short length, short InData, byte [] OutData, short OutOffset )
	{
		short totallength = (short) ((short)2 + (short)2);
		short Offset = OutOffset;
		OutData[ Offset++ ] = tag;
		OutData[ Offset++] = (byte)length;

		Util.setShort( OutData,  Offset,  InData);
		
		BuildLength = (short)(Offset + 2 - OutOffset);
		return OutData;
	}
	public byte [] BuildTLVStructure( byte tag, short length, byte InData, byte [] OutData, short OutOffset )
	{
		short totallength = (short) ((short)2 + (short)1);
		short Offset = OutOffset;
		OutData[ Offset++ ] = tag;
		OutData[ Offset++] = (byte)length;
		OutData[Offset++] = InData;
		
		BuildLength = (short)(Offset  - OutOffset);
		return OutData;
	}
	
	public short GetBuildTLVLength()
	{
		return BuildLength;
	}
	
}
