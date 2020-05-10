package sec.dpas;


import java.security.PublicKey;

import java.util.ArrayList;

import java.io.Serializable;


public class Announcement implements Serializable{

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

  public PublicKey getKey(){ return _pubkey; }

  public char[] getMessage(){ return _message; }

  public ArrayList<Announcement> getReferences(){ return _references; }

  public byte[] getSignature() { return _signature; }

  public String getId() { return _id; }

  public int getTimeStamp() { return _timeStamp; }

  public boolean isGeneralBoard() { return _generalBoard; }

}
