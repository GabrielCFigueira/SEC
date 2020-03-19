package sec.dpas;

import java.util.Hashtable;

import java.security.Key;

public class Announcement{

  private Key _pubkey;
  private char[] _message;
  private Announcement[] _references;

  public Announcement(Key pubkey,char[] msg, Announcement[] refs){
    _pubkey = pubkey;
    _message = msg;
    _references = refs;
  }

  public Key getKey(){
    return _pubkey;
  }

  public char[] getMessage(){
    return _message;
  }

  public Announcement[] getReferences(){
    return _references;
  }

  /*public void addReference(Announcement a){
    _references.put(a);
  }*/

}
