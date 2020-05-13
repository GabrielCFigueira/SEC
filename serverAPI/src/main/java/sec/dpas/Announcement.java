package sec.dpas;


import java.security.PublicKey;

import java.util.ArrayList;

import java.io.Serializable;
import java.lang.Comparable;

public class Announcement implements Serializable, Comparable<Announcement>{

  private PublicKey _pubkey;
  private String _id;
  private int _timeStamp;
  private boolean _generalBoard;
  private char[] _message;
  private ArrayList<Announcement> _references;
  private byte[] _signature;

  public Announcement(PublicKey pubkey, char[] msg, ArrayList<Announcement> refs, byte[] signature, String id, int timeStamp, boolean generalBoard){
    _pubkey = pubkey;
    _id = id;
    _message = msg;
    _references = refs;
    _timeStamp = timeStamp;
    _generalBoard = generalBoard;
    _signature = signature;
  }

  public int compareTo(Announcement a) {
    if(this.getTimeStamp() > a.getTimeStamp())
      return 1;
    else if(this.getTimeStamp() < a.getTimeStamp())    
      return -1;
    else {
      String key1, key2;
      key1 = Crypto.getBase64(this.getKey());
      key2 = Crypto.getBase64(a.getKey());
      return key1.compareTo(key2);
    }
  }

  public PublicKey getKey(){ return _pubkey; }

  public char[] getMessage(){ return _message; }

  public ArrayList<Announcement> getReferences(){ return _references; }

  public byte[] getSignature() { return _signature; }

  public String getId() { return _id; }

  public int getTimeStamp() { return _timeStamp; }

  public boolean isGeneralBoard() { return _generalBoard; }

}
