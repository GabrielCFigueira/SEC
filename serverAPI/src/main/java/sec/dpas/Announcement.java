package sec.dpas;


import java.security.Key;

import java.io.Serializable;


public class Announcement implements Serializable{

  private Key _pubkey;
  //private int _id;
  private char[] _message;
  private Announcement[] _references;
  private byte[] _signature;

  public Announcement(Key pubkey, char[] msg, Announcement[] refs, byte[] signature){
    _pubkey = pubkey;
    //_id = 
    _message = msg;
    _references = refs;
    _signature = signature;
  }

  public Key getKey(){ return _pubkey; }

  public char[] getMessage(){ return _message; }

  public Announcement[] getReferences(){ return _references; }

  public byte[] getSignature() { return _signature; }

  /*public void addReference(Announcement a){
    _references.put(a);
  }*/
}
