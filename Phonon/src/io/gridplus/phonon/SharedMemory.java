package io.gridplus.phonon;

/**
 * Keep references to data structures shared across applet instances of this package.
 */
class SharedMemory {
  /** The NDEF data file. Read through the NDEFApplet. **/
  static final byte[] ndefDataFile = new byte[SecureChannel.SC_MAX_PLAIN_LENGTH];
}
