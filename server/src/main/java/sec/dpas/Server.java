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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.Exception;

import java.util.Arrays;
import java.util.Hashtable;
import java.util.ArrayList;
import java.util.List;

import sec.dpas.exceptions.SigningException;

/**
 * Server
 *
 */
public class Server implements ServerAPI{

    private Hashtable<PublicKey, ArrayList<Announcement>> _announcementB;
    private Hashtable<PublicKey, Long> _nonceTable;
    private ArrayList<Announcement> _generalB;
    private Key _serverKey;

    public Server() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        _announcementB = new Hashtable<PublicKey, ArrayList<Announcement>>();
        _nonceTable = new Hashtable<PublicKey, Long>();
        _generalB = new ArrayList<Announcement>();
        _serverKey = Crypto.readPrivateKey("../resources/key.store", "server", "keystore", "server");
    }


    private boolean verifyArguments(PublicKey pubkey, byte[] signature) {
        if(pubkey == null || signature == null)
		return false;
	else
		return true;
    }

    private boolean verifyArguments(PublicKey pubkey, Announcement a, byte[] signature) {
        if(pubkey == null || a == null || signature == null)
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

    public Response getNonce(PublicKey pubkey, long clientNonce, byte[] signature) {

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

        if(!hasPublicKey(pubkey)){
            return constructResponse("No such user registered", clientNonce);
        }

	long serverNonce = Crypto.generateNonce();
	_nonceTable.put(pubkey, serverNonce);
	return constructResponse("Nonce generated", clientNonce, serverNonce);
    }


    public Response register(PublicKey pubkey, long clientNonce, byte[] signature) {

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

        if(_announcementB.containsKey(pubkey))
            return constructResponse("User was already registered", clientNonce);

        _announcementB.put(pubkey,new ArrayList<Announcement>());
	_nonceTable.put(pubkey, (long) 0);

        try {saveToFile("board");}
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        return constructResponse("User registered", clientNonce);
    }


    public Response post(PublicKey pubkey, Announcement a, long clientNonce, long serverNonce, byte[] signature) {

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

        if(!hasPublicKey(pubkey)){
            return constructResponse("No such user registered", clientNonce);
        }

	if(_nonceTable.get(pubkey) == (long) 0 || _nonceTable.get(pubkey) != serverNonce)
	    return constructResponse("Invalid nonce", clientNonce);
	_nonceTable.replace(pubkey, (long) 0);

	getUserAnnouncements(pubkey).add(a);
        try {saveToFile("board");}
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        return constructResponse("Announcement posted", clientNonce);
    }

    public Response postGeneral(PublicKey pubkey, Announcement a, long clientNonce, long serverNonce, byte[] signature){

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

        if(!hasPublicKey(pubkey)){
            return constructResponse("No such user registered", clientNonce);
        }

	if(_nonceTable.get(pubkey) == (long) 0 || _nonceTable.get(pubkey) != serverNonce)
	    return constructResponse("Invalid nonce", clientNonce);
	_nonceTable.replace(pubkey, (long) 0);

	getGenAnnouncements().add(a);
        try {saveToFile("genboard");}
        catch (IOException e){
            System.out.println(e.getMessage());
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

    private Announcement getUserAnnouncement(PublicKey pubkey, int id){ //falta verificar que pode nao haver anns com esta pubkey
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

    public Response read(PublicKey pubkey, int number, PublicKey senderKey, long clientNonce, long serverNonce, byte[] signature) {

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

	if(_nonceTable.get(senderKey) == (long) 0 || _nonceTable.get(senderKey) != serverNonce)
	    return constructResponse("Invalid nonce", clientNonce);
	_nonceTable.replace(senderKey, (long) 0);

	try{
            loadFromFile("board");
        }
        catch(IOException e){
            System.out.println(e.getMessage());
        }
        catch(ClassNotFoundException e){
            System.out.println(e.getMessage());
        }
        ArrayList<Announcement> userAnn = getUserAnnouncements(pubkey);
        return readFrom(userAnn, number, clientNonce);
    }

    public Response readGeneral(int number, PublicKey senderKey, long clientNonce, long serverNonce, byte[] signature) {

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

	if(_nonceTable.get(senderKey) == (long) 0 || _nonceTable.get(senderKey) != serverNonce)
	    return constructResponse("Invalid nonce", clientNonce);
	_nonceTable.replace(senderKey, (long) 0);

	try{
            loadFromFile("genboard");
        }
        catch(IOException e){
            System.out.println(e.getMessage());
        }
        catch(ClassNotFoundException e){
            System.out.println(e.getMessage());
        }
        ArrayList<Announcement> genAnn = getGenAnnouncements();
        return readFrom(genAnn, number, clientNonce);
    }

    private Response readFrom(ArrayList<Announcement> ann, int number, long clientNonce) {

	if (number < 0)
            return constructResponse("Tried to read with a negative number.", clientNonce);
        else if (number > ann.size())
            return constructResponse("Tried to read with a number bigger than the number of announcements for that board.", clientNonce);
	else if (number == 0)
	    return constructResponse("read successful", ann, clientNonce);
	else {
	    ArrayList<Announcement> sublist;
	    try {
	        sublist = new ArrayList<Announcement>(ann.subList(ann.size() - number, ann.size()));
	    } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
	        return constructResponse("Thanos has snapped and the Universe stopped making sense", clientNonce);
	    }
	    return constructResponse("read successful", sublist, clientNonce);
	}
    }

    private Response constructResponse(String statusCode, long clientNonce, long serverNonce) {
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

    private  Response constructResponse(String statusCode, long clientNonce) {
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
        return new Response(statusCode, null, clientNonce, serverSignature);
    }

    private Response constructResponse(String statusCode, ArrayList<Announcement> an, long clientNonce) {
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
            FileOutputStream fileOutput = new FileOutputStream("../resources/" + path + ".txt");
            ObjectOutputStream output = new ObjectOutputStream(fileOutput);
            if(path.equals("board")){
                output.writeObject(getAnnouncements());
            }
            else{
                output.writeObject(getGenAnnouncements());
            }

            output.close();
            fileOutput.close();
        }
        catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

    private void loadFromFile(String path) throws IOException, ClassNotFoundException{
        try{
            FileInputStream fileInput = new FileInputStream("../resources/" + path + ".txt");
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


    public static void main(String args[]) {
        int registryPort = 1099;
        System.out.println("#####");

        try {
            Server obj = new Server();
            //src.hello.Server obj = new src.hello.Server();
            ServerAPI stub = (ServerAPI) UnicastRemoteObject.exportObject(obj, 0);

            // Bind the remote object's stub in the registry
            //Registry registry = LocateRegistry.getRegistry();
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
