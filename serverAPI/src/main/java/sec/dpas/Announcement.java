package sec.dpas;


import java.security.Key;

import java.util.ArrayList;

import java.io.Serializable;


public class Announcement implements Serializable{

  private Key _pubkey;
  private String _id;
  private char[] _message;
  private ArrayList<Announcement> _references;
  private byte[] _signature;

  public Announcement(Key pubkey, char[] msg, ArrayList<Announcement> refs, byte[] signature, String id){
    _pubkey = pubkey;
    _id = id;
    _message = msg;
    _references = refs;
    _signature = signature;
  }

  public Key getKey(){ return _pubkey; }

  public char[] getMessage(){ return _message; }

  public ArrayList<Announcement> getReferences(){ return _references; }

  public byte[] getSignature() { return _signature; }

  public String getId() { return _id; }

}
