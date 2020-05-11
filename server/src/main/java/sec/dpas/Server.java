package sec.dpas;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.Naming;

/* Java Crypto imports */
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.File;

import java.util.Arrays;
import java.util.Hashtable;
import java.util.ArrayList;
import java.util.List;
import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

import java.nio.file.Files;
import java.nio.file.Paths;
import static java.nio.file.StandardCopyOption.*;

import sec.dpas.exceptions.SigningException;

import java.math.BigInteger;

/**
 * Server
 *
 */

public class Server implements ServerAPI{

    private class Broadcast {

	private boolean sentecho = false;
	private boolean sentready = false;
	private boolean delivered = false;

	private boolean sentAbort = false;
	private boolean aborted = false;

	private int echos = 0;
	private int readys = 0;
	private int aborts = 0;

	//private ConcurrentHashMap<Integer, Integer> echos = new ConcurrentHashMap<Integer, Integer>();
	//private ConcurrentHashMap<Integer, Integer> readys = new ConcurrentHashMap<Integer, Integer>();
	//private ConcurrentHashMap<Integer, Integer> aborts = new ConcurrentHashMap<Integer, Integer>();

    }

    public void echo(int serverId, Announcement a, byte[] signature) {
	    //signature verification
      boolean status1 = false;
      boolean status2 = false;

      try {
          Message message = new Message();
          message.appendObject(serverId);
          message.appendObject(a);
          if(!Crypto.verifySignature(a.getKey(), message.getByteArray(), signature)) {
              status1 = true;
          }
      } catch(IOException e) {
          System.out.println(e.getMessage());
      }
	    ///announcement verification
      try {
          Message message = new Message();
          message.appendObject(a.getKey());
          message.appendObject(a.getMessage());
          message.appendObject(a.getReferences());
          message.appendObject(a.getId());
          message.appendObject(a.getTimeStamp());
          message.appendObject(a.isGeneralBoard());
          if(!Crypto.verifySignature(Crypto.readPublicKey("../resources/server" + serverId + ".pub"), message.getByteArray(), signature)) {
              status2 = true;
          }
      } catch(IOException e) {
          System.out.println(e.getMessage());
      }
      System.out.println("status1"+status1);
      System.out.println("status2"+status2);
      if(status1 == true && status2 == true){
	       echo(serverId, a);
      }
      //echo(serverId, a);
    }


    private void echo(int serverId, Announcement a) {

	Broadcast brd;
	synchronized(_broadcastTable) {
	    if(!_broadcastTable.containsKey(new String(a.getSignature())))
	    	_broadcastTable.put(new String(a.getSignature()), new Broadcast());
	    brd = _broadcastTable.get(new String(a.getSignature()));

/*	if(!brd.echos.containsKey(serverId)) {
	    brd.echos.put(serverId, serverId);

	}*/

	brd.echos++;


	if(brd.sentready == false) {
	    int max = brd.echos;
	    if(_pendingWrites.get(a.getKey())) {
		brd.sentready = true;
		brd.sentAbort = true;
		sendReady(a, true);
	    }
	    else if(max >= Math.round((((float) _N) + _f) / 2)) {
		brd.sentready = true;
		_pendingWrites.put(a.getKey(), true);
		sendReady(a, false);
	    }
	}
	}

    }



    public void ready(int serverId, Announcement a, boolean abort, byte[] signature) {
	// signature verification
  try {
      Message message = new Message();
      message.appendObject(serverId);
      message.appendObject(a);
      if(!Crypto.verifySignature(a.getKey(), message.getByteArray(), signature)) {
          //do sth
      }
  } catch(IOException e) {
      System.out.println(e.getMessage());
  }
  ///announcement verification

  try {
      Message message = new Message();
      message.appendObject(a.getKey());
      message.appendObject(a.getMessage());
      message.appendObject(a.getReferences());
      message.appendObject(a.getId());
      message.appendObject(a.getTimeStamp());
      message.appendObject(a.isGeneralBoard());
      if(!Crypto.verifySignature(a.getKey(), message.getByteArray(), a.getSignature())) {
          //pls do sth. I have a wife and kids
      }
  } catch(IOException e) {
      System.out.println(e.getMessage());
  }

	Broadcast brd;
	synchronized(_broadcastTable) {
	    if(!_broadcastTable.containsKey(new String(a.getSignature())))
	    	_broadcastTable.put(new String(a.getSignature()), new Broadcast());
	    brd = _broadcastTable.get(new String(a.getSignature()));

//	if(!brd.readys.containsKey(serverId) && !brd.aborts.containsKey(serverId)) {
	    if(abort)
		brd.aborts++;
	    else
	    	brd.readys++;
//	}


	int max = brd.readys;

	System.out.println(max);

	if(brd.sentready == false ) {
	    if(_pendingWrites.get(a.getKey())) {
		brd.sentready = true;
		brd.sentAbort = true;
		sendReady(a, true);
	    }
	    else if(max > _f) {
	    	brd.sentready = true;
	    	sendReady(a, false);
	    }
	} else if(max > 2 * _f && brd.delivered == false) {
	    brd.delivered = true;
	    System.out.println("delivered");
	    getUserAnnouncements(a.getKey()).add(a);
	    _pendingWrites.put(a.getKey(), false);
	    try {
	    	_broadcastTable.notifyAll();
	    } catch (Exception e) {
		System.out.println("1" + e.getMessage());
		System.exit(-1);
	    }
	} else if(_N - brd.aborts < 2 * _f + 1) {
	    brd.delivered = true;
	    brd.aborted = true;
	    if(!brd.sentAbort)
		_pendingWrites.put(a.getKey(), false);
	    try {
	    	brd.notifyAll();
	    } catch (Exception e) {
		System.out.println(e.getMessage());
		System.exit(-1);
	    }
	}
	}

    }

    public void sendReady(Announcement a, boolean abort) {
	//create signature
	ExecutorService threadpool = Executors.newCachedThreadPool();
	for (String id : _servers.keySet()) {
	    threadpool.submit(() -> { try {
	    	    ServerAPI stub = (ServerAPI) Naming.lookup(_servers.get(id));
		    stub.ready(_id, a, abort, signBroadcast(a));
	    } catch (Exception e) {
		    System.out.println(e.getMessage());
	    }});
	}
    }

    public void sendEcho(Announcement a) {
	//create signature
	ExecutorService threadpool = Executors.newCachedThreadPool();
	for (String id : _servers.keySet()) {
	    threadpool.submit(() -> { try {
	    	    ServerAPI stub = (ServerAPI) Naming.lookup(_servers.get(id));
		    stub.echo(_id, a, signBroadcast(a));
	    } catch (Exception e) {
		    System.out.println(e.getMessage());
	    }});
	}
    }

  private byte[] signBroadcast(Announcement a){
    byte[] signature = null;
    try {
      Message message = new Message();
      message.appendObject(_id);
      message.appendObject(a);
      signature = Crypto.sign(_serverKey, message.getByteArray());
    }
    catch(Exception e){
      System.out.println(e.getMessage());
    }
    return signature;
  }


    private ConcurrentHashMap<String, Broadcast> _broadcastTable = new ConcurrentHashMap<String, Broadcast>();
    private Hashtable<PublicKey, ArrayList<Announcement>> _announcementB;
    private Hashtable<PublicKey, String> _nonceTable;
    private ArrayList<Announcement> _generalB;
    private Key _serverKey;
    private PublicKey _serverPubKey;
    private int _id = 1;
    private int _N = 4;
    private int _f = 1;
    private Hashtable<String, String> _servers = new Hashtable<String, String>();

    private Hashtable<PublicKey, Boolean> _pendingWrites = new Hashtable<PublicKey, Boolean>();
    private boolean _pendingGeneralWrite = false;
    private boolean _broadcast = false;

    public Server(String keyName, String keyPass) throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        _announcementB = new Hashtable<PublicKey, ArrayList<Announcement>>();
        _nonceTable = new Hashtable<PublicKey, String>();
        _generalB = new ArrayList<Announcement>();
        _serverKey = Crypto.readPrivateKey("../resources/key.store", keyName, "keystore", keyPass);
        _serverPubKey = Crypto.readPublicKey("../resources/server" + _id + ".pub");


        File f = new File("../resources/board" + _id + ".txt");
        if(f.isFile()) {

            try{
                loadFromFile("board");
            }
            catch(ClassNotFoundException e){
                System.out.println(e.getMessage());
                _announcementB = new Hashtable<PublicKey, ArrayList<Announcement>>();
            }
        }

        f = new File("../resources/genboard" + _id + ".txt");
        if(f.isFile()) {

            try{
                loadFromFile("genboard");
            }
            catch(ClassNotFoundException e){
                System.out.println(e.getMessage());
                _generalB = new ArrayList<Announcement>();
            }
        }

	generateUrls();
    }

    private void generateUrls() {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("../resources/servers.txt"));
            String line = reader.readLine();
            String[] words;
            while (line != null) {
                words = line.split(" ");
		if(!words[0].equals(_id))
		    _servers.put(words[0], words[1]);
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public Server() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        this("server", "server");
    }

    public Server(int id) throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
	this("server" + id, "server" + id);
  _id = id;
  _broadcast = true;
    }

    public Server(int id, int N, int f) throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
	this(id);
  	_id = id;
	_N = N;
	_f = f;
    }

    public void cleanup() {
        synchronized(_announcementB) {
            synchronized(_nonceTable) {
                synchronized(_generalB) {

                    File board = new File("../resources/board" + _id + ".txt");
                    File genboard = new File("../resources/genboard" + _id + ".txt");

                    board.delete();
                    genboard.delete();

                    _announcementB = new Hashtable<PublicKey, ArrayList<Announcement>>();
                    _nonceTable = new Hashtable<PublicKey, String>();
                    _generalB = new ArrayList<Announcement>();
                }
            }
        }
    }

    public void crash() {
        System.exit(1);
    }


    private boolean verifyArguments(PublicKey pubkey, byte[] signature) {
        if(pubkey == null || signature == null)
            return false;
        else
            return true;
    }

    private boolean verifyArguments(PublicKey pubkey, Announcement a, byte[] signature) {
        if(pubkey == null || a == null || signature == null || a.getMessage().length > 255 || a.getMessage().length == 0)
            return false;
        else
            return true;
    }

    private boolean verifyArguments(PublicKey pubkey, PublicKey senderKey, byte[] signature) {
        if(pubkey == null || senderKey == null || signature == null)
            return false;
        else
            return true;
    }

    public Response getNonce(PublicKey pubkey, String clientNonce, byte[] signature) {

        if(!verifyArguments(pubkey, signature))
            return constructResponse("Invalid arguments", clientNonce);

        //verify signature
        try {
            Message message = new Message();
            message.appendObject(pubkey);
            message.appendObject(clientNonce);
            if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

        String serverNonce;

        synchronized(_announcementB) {
            synchronized(_nonceTable) {
                if(!hasPublicKey(pubkey))
                    return constructResponse("No such user registered", clientNonce);
                serverNonce = Crypto.generateNonce();
                _nonceTable.put(pubkey, serverNonce);
            }
        }
        return constructResponse("Nonce generated", clientNonce, serverNonce);
    }


    public Response register(PublicKey pubkey, String clientNonce, byte[] signature) {
        if(!verifyArguments(pubkey, signature))
            return constructResponse("Invalid arguments", clientNonce);

        //verify signature
        try {
            Message message = new Message();
            message.appendObject(pubkey);
            message.appendObject(clientNonce);
            if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

        synchronized(_announcementB) {
            synchronized(_nonceTable) {
		_pendingWrites.put(pubkey, false);
                if(hasPublicKey(pubkey))
                    return constructResponse("User was already registered", clientNonce);
                _announcementB.put(pubkey,new ArrayList<Announcement>());
                _nonceTable.put(pubkey, "0");
            }

            try {saveToFile("board");}
            catch (IOException e){
                System.out.println(e.getMessage());
            }
        }

        return constructResponse("User registered", clientNonce);
    }


    public Response post(PublicKey pubkey, Announcement a, String clientNonce, String serverNonce, byte[] signature) {

        if(!verifyArguments(pubkey, a, signature))
            return constructResponse("Invalid arguments", clientNonce);

        //verify signature
        try {
            Message message = new Message();
            message.appendObject(pubkey);
            message.appendObject(a);
            message.appendObject(clientNonce);
            message.appendObject(serverNonce);
            if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

        //verify Announcement signature
        try {
            Message message = new Message();
            message.appendObject(a.getKey());
            message.appendObject(a.getMessage());
            message.appendObject(a.getReferences());
            message.appendObject(a.getId());
	    message.appendObject(a.getTimeStamp());
	    message.appendObject(a.isGeneralBoard());
            if(!Crypto.verifySignature(a.getKey(), message.getByteArray(), a.getSignature())) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

	if(a.isGeneralBoard())
	    return constructResponse("Wrong Board", clientNonce);

        synchronized(_nonceTable) {
            if(!hasPublicKey(pubkey) || !hasPublicKey(a.getKey())){
                return constructResponse("No such user registered", clientNonce);
            }
            if(_nonceTable.get(pubkey).equals("0") || !_nonceTable.get(pubkey).equals(serverNonce))
                return constructResponse("Invalid nonce", clientNonce);
            _nonceTable.replace(pubkey,  "0");
	}
	int boardSize;

	synchronized(_announcementB) {
	    boardSize = getUserAnnouncements(a.getKey()).size();
	}
	if (boardSize < a.getTimeStamp() - 1)
	    return constructResponse("Invalid Announcement TimeStamp", clientNonce);


	String status = "Announcement posted";

	if(boardSize == a.getTimeStamp() - 1) {
	    if(_broadcast) {
            	echo(_id, a);
	    	sendEcho(a);

	    	try {
	    	    synchronized(_broadcastTable) {
        	    	Broadcast brd = _broadcastTable.get(new String(a.getSignature()));
	    	    	while(!brd.delivered)
		    	     _broadcastTable.wait();
	    	    	if(brd.aborted)
		    	    status = "Announcement aborted";
	    	    }
	    	} catch (InterruptedException e) {
		    System.out.println(e.getMessage());
		    System.exit(-1);
	    	}
	    }
	    else {
                getUserAnnouncements(a.getKey()).add(a);
		try {saveToFile("board");}
            	catch (IOException e){
                    System.out.println(e.getMessage());
            	}
	    }
	}

        return constructResponse(status, clientNonce);
    }

    public Response postGeneral(PublicKey pubkey, Announcement a, String clientNonce, String serverNonce, byte[] signature){

        if(!verifyArguments(pubkey, a, signature))
            return constructResponse("Invalid arguments", clientNonce);

        try {
            Message message = new Message();
            message.appendObject(pubkey);
            message.appendObject(a);
            message.appendObject(clientNonce);
            message.appendObject(serverNonce);
            if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

        //verify Announcement signature
        try {
            Message message = new Message();
            message.appendObject(a.getKey());
            message.appendObject(a.getMessage());
            message.appendObject(a.getReferences());
            message.appendObject(a.getId());
	    message.appendObject(a.getTimeStamp());
            message.appendObject(a.isGeneralBoard());
	    if(!Crypto.verifySignature(a.getKey(), message.getByteArray(), a.getSignature())) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

	if(!a.isGeneralBoard())
	    return constructResponse("Wrong Board", clientNonce);

	synchronized(_generalB) {
            synchronized(_nonceTable) {
                if(!hasPublicKey(pubkey) || !hasPublicKey(a.getKey())){
                    return constructResponse("No such user registered", clientNonce);
                }
                if(_nonceTable.get(pubkey).equals("0") || !_nonceTable.get(pubkey).equals(serverNonce))
                    return constructResponse("Invalid nonce", clientNonce);
                _nonceTable.replace(pubkey, "0");
		if(getGenAnnouncements().size() == a.getTimeStamp() - 1)
                    getGenAnnouncements().add(a);
		else if (getGenAnnouncements().size() < a.getTimeStamp() - 1)
	            return constructResponse("Invalid Announcement TimeStamp", clientNonce);
            }

            try {saveToFile("genboard");}
            catch (IOException e){
                System.out.println(e.getMessage());
            }
        }

        return constructResponse("General announcement posted", clientNonce);
    }

    private boolean hasPublicKey(PublicKey key) {
        return _announcementB.containsKey(key);
    }

    private ArrayList<Announcement> getUserAnnouncements(PublicKey pubkey){
        return _announcementB.get(pubkey);
    }

    private ArrayList<Announcement> getGenAnnouncements(){
        return _generalB;
    }

    private ArrayList<Announcement> getAllUserAnnouncements(PublicKey pubkey){
        ArrayList<Announcement> all = getUserAnnouncements(pubkey);
        for (Announcement ann : _generalB){
            if(ann.getKey().equals(pubkey)){
                all.add(ann);
            }
        }
        return all;
    }

    private Announcement getUserAnnouncement(PublicKey pubkey, String id){ //falta verificar que pode nao haver anns com esta pubkey
        for (Announcement ann : getAllUserAnnouncements(pubkey)){
            if(ann.getId() == id){
                return ann;
            }
        }
        return null;
    }

    private Hashtable<PublicKey, ArrayList<Announcement>> getAnnouncements(){
        return _announcementB;
    }

    public Response read(PublicKey pubkey, int number, PublicKey senderKey, String clientNonce, String serverNonce, byte[] signature) {

        if(!verifyArguments(pubkey, senderKey, signature))
            return constructResponse("Invalid arguments", clientNonce);

        //verify signature
        try {
            Message message = new Message();
            message.appendObject(pubkey);
            message.appendObject(number);
            message.appendObject(senderKey);
            message.appendObject(clientNonce);
            message.appendObject(serverNonce);
            if(!Crypto.verifySignature(senderKey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

        if(!hasPublicKey(pubkey) || !hasPublicKey(senderKey)){
            return constructResponse("No such user registered", clientNonce);
        }

        synchronized(_nonceTable) {
            if(_nonceTable.get(pubkey).equals("0") || !_nonceTable.get(pubkey).equals(serverNonce))
                return constructResponse("Invalid nonce", clientNonce);
            _nonceTable.replace(senderKey, "0");
        }

        synchronized(_announcementB) {
            ArrayList<Announcement> userAnn = getUserAnnouncements(pubkey);
            return readFrom(userAnn, number, clientNonce);
        }
    }

    public Response readGeneral(int number, PublicKey senderKey, String clientNonce, String serverNonce, byte[] signature) {

        if(!verifyArguments(senderKey, signature))
            return constructResponse("Invalid arguments", clientNonce);

        //verify signature
        try {
            Message message = new Message();
            message.appendObject(number);
            message.appendObject(senderKey);
            message.appendObject(clientNonce);
            message.appendObject(serverNonce);
            if(!Crypto.verifySignature(senderKey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed", clientNonce);
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage(), clientNonce);
        }

        if(!hasPublicKey(senderKey)){
            return constructResponse("No such user registered", clientNonce);
        }

        synchronized(_nonceTable) {
            if(_nonceTable.get(senderKey).equals("0") || !_nonceTable.get(senderKey).equals(serverNonce))
                return constructResponse("Invalid nonce", clientNonce);
            _nonceTable.replace(senderKey, "0");
        }

        synchronized(_generalB) {
            ArrayList<Announcement> genAnn = getGenAnnouncements();
            return readFrom(genAnn, number, clientNonce);
        }
    }

    private Response readFrom(ArrayList<Announcement> ann, int number, String clientNonce) {

        if (number < 0)
            return constructResponse("Tried to read with a negative number.", (ArrayList<Announcement>) null, clientNonce);
        else if (number > ann.size())
            return constructResponse("Tried to read with a number bigger than the number of announcements for that board.", (ArrayList<Announcement>) null, clientNonce);
        else if (number == 0)
            return constructResponse("read successful", ann, clientNonce);
        else {
            ArrayList<Announcement> sublist;
            try {
                sublist = new ArrayList<Announcement>(ann.subList(ann.size() - number, ann.size()));
            } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
                return constructResponse("Thanos has snapped and the Universe stopped making sense", (ArrayList<Announcement>) null, clientNonce);
            }
            return constructResponse("read successful", sublist, clientNonce);
        }
    }

    public Response constructResponse(String statusCode, String clientNonce, String serverNonce) {
        Message message = new Message();
        try {
            message.appendObject(statusCode);
            message.appendObject(clientNonce);
            message.appendObject(serverNonce);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        byte[] serverSignature = null;
        try {
            serverSignature = Crypto.sign(_serverKey, message.getByteArray());
        } catch (SigningException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        return new Response(statusCode, clientNonce, serverNonce, serverSignature);
    }

    public Response constructResponse(String statusCode, String clientNonce) {
        Message message = new Message();
        try {
            message.appendObject(statusCode);
            message.appendObject(clientNonce);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        byte[] serverSignature = null;
        try {
            serverSignature = Crypto.sign(_serverKey, message.getByteArray());
        } catch (SigningException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        return new Response(statusCode,(ArrayList<Announcement>) null, clientNonce, serverSignature);
    }

    public Response constructResponse(String statusCode, ArrayList<Announcement> an, String clientNonce) {
        Message message = new Message();

        try {
            message.appendObject(statusCode);
            message.appendObject(clientNonce);
            message.appendObject(an);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        byte[] serverSignature = null;
        try {
            serverSignature = Crypto.sign(_serverKey, message.getByteArray());
        } catch (SigningException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        return new Response(statusCode, an, clientNonce, serverSignature);
    }

    private void saveToFile(String path) throws IOException{
        try{
            FileOutputStream fileOutput = new FileOutputStream("../resources/" + path + _id + "_temp.txt");
            ObjectOutputStream output = new ObjectOutputStream(fileOutput);
            if(path.equals("board")){
                output.writeObject(getAnnouncements());
            }
            else{
                output.writeObject(getGenAnnouncements());
            }

            output.close();
            fileOutput.close();
            Files.move(Paths.get("../resources/" + path +  _id + "_temp.txt"), Paths.get("../resources/" + path + _id + ".txt"), REPLACE_EXISTING, ATOMIC_MOVE);
        }
        catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

    private void loadFromFile(String path) throws IOException, ClassNotFoundException{
        try{
            //  FileInputStream fileInput = new FileInputStream("../resources/" + path + ".txt");
            FileInputStream fileInput = new FileInputStream("../resources/" + path + _id + ".txt");
            ObjectInputStream input = new ObjectInputStream(fileInput);
            if(path.equals("board")){
                _announcementB = (Hashtable<PublicKey, ArrayList<Announcement>>) input.readObject();
            }
            else{
                _generalB = (ArrayList<Announcement>) input.readObject();
            }

            input.close();
            fileInput.close();
        }
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        catch (ClassNotFoundException e){
            System.out.println(e.getMessage());
        }
    }

    public int getId() { return _id; }





    public static void main(String args[]) {
        int registryPort = 8000;
        System.out.println("#####");

        try {
	    Server obj;
	    if(args.length == 1){
		    obj = new Server(Integer.parseInt(args[0]));
      	    }
	    else if(args.length == 2) {
		    obj = new Server(args[0], args[1]);
	    }
	    else if(args.length == 3) {
		    obj = new Server(Integer.parseInt(args[0]), Integer.parseInt(args[1]), Integer.parseInt(args[2]));
	    }
	    else
		    obj = new Server();
            //src.hello.Server obj = new src.hello.Server();
            ServerAPI stub = (ServerAPI) UnicastRemoteObject.exportObject(obj, 0);

            // Bind the remote object's stub in the registry
            //Registry registry = LocateRegistry.getRegistry();i
	    BufferedReader reader;
	    try {
	    	reader = new BufferedReader(new FileReader("../resources/servers.txt"));
		String line = reader.readLine();
		while (line != null) {
			String id = line.split(" ")[0];
			if(Integer.parseInt(id) == obj.getId())
				registryPort = Integer.parseInt(line.split(" ")[1].split("/")[2].split(":")[1]);
			line = reader.readLine();
		}
		reader.close();
	    } catch (IOException e) {
		    e.printStackTrace();
	    }
            Registry registry = LocateRegistry.createRegistry(registryPort); //no garbage collection
            registry.bind("ServerAPI", stub);
            //Naming.rebind("//localhost:1099/ServerAPI");

            System.err.println("Server ready");
            System.out.println("Awaiting connections");
            System.out.println("Press enter to shutdown");
            System.in.read();
            System.exit(0);
        } catch (IndexOutOfBoundsException e) {
            System.out.println("Exception thrown : " + e);
        } catch (IllegalArgumentException e) {
            System.out.println("Exception thrown : " + e);
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }

}
