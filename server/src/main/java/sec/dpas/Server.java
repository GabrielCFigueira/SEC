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
import java.sql.Timestamp;
import java.util.Hashtable;
import java.util.ArrayList;
import java.util.List;

import sec.dpas.exceptions.SigningException;

/**
 * TODO!
 *
 */
public class Server implements ServerAPI{

    private Hashtable<PublicKey, ArrayList<Announcement>> _announcementB;
    private ArrayList<Announcement> _generalB;
    private Key _serverKey;

    public Server() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        _announcementB = new Hashtable<PublicKey, ArrayList<Announcement>>();
        _generalB = new ArrayList<Announcement>();
        _serverKey = Crypto.readPrivateKey("../resources/key.store", "server", "keystore", "server");
    }

    private  Response constructResponse(String statusCode) {
        Message message = new Message();
        Timestamp currentTs = new Timestamp(System.currentTimeMillis());
        try {
            message.appendObject(statusCode);
            message.appendObject(currentTs);
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
        return new Response(statusCode, null, currentTs, serverSignature);
    }

    private Response constructResponse(String statusCode, ArrayList<Announcement> an) {
        Message message = new Message();
        Timestamp currentTs = new Timestamp(System.currentTimeMillis());

        try {
            message.appendObject(statusCode);
            message.appendObject(currentTs);
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
        return new Response(statusCode, an, currentTs, serverSignature);
    }

    public Response register(PublicKey pubkey, Timestamp ts, byte[] signature) {

        //verify signature
        try {
            Message message = new Message();
            message.appendObject(pubkey);
            message.appendObject(ts);
            if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
                return constructResponse("Signature verification failed");
            }
        } catch(IOException e) {
            return constructResponse(e.getMessage());
        }

        Timestamp currentTs = new Timestamp(System.currentTimeMillis());
        if(Math.abs(ts.getTime() - currentTs.getTime()) > 5000)
            return constructResponse("Timestamp differs more than " + (ts.getTime() - currentTs.getTime()) + " milliseconds than the current server time");

        if(_announcementB.containsKey(pubkey))
            return constructResponse("User was already registered");

        _announcementB.put(pubkey,new ArrayList<Announcement>());
        try {saveToFile("board");}
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        return constructResponse("User registered");
    }

    public Response post(PublicKey pubkey, Announcement a, Timestamp ts, byte[] signature) {

      //verify signature
      try {
	Message message = new Message();
	message.appendObject(pubkey);
	message.appendObject(a);
	message.appendObject(ts);
	if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
	  return constructResponse("Signature verification failed");
	}
      } catch(IOException e) {
	  return constructResponse(e.getMessage());
      }

      Timestamp currentTs = new Timestamp(System.currentTimeMillis());
      if(Math.abs(ts.getTime() - currentTs.getTime()) > 5000)
	return constructResponse("Timestamp differs more than " + (ts.getTime() - currentTs.getTime()) + " milliseconds than the current server time");


      if(!hasPublicKey(pubkey)){
        return constructResponse("No such user registered. needs to register before posting");
      }

        getUserAnnouncements(pubkey).add(a);
        try {saveToFile("board");}
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        return constructResponse("Announcement posted");
    }

    public Response postGeneral(PublicKey pubkey, Announcement a, Timestamp ts, byte[] signature){

      try {
	       Message message = new Message();
	       message.appendObject(pubkey);
	       message.appendObject(a);
	       message.appendObject(ts);
	       if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature)) {
	          return constructResponse("Signature verification failed");
	         }
         } catch(IOException e) {
	          return constructResponse(e.getMessage());
      }

      Timestamp currentTs = new Timestamp(System.currentTimeMillis());
      if(Math.abs(ts.getTime() - currentTs.getTime()) > 5000)
	       return constructResponse("Timestamp differs more than " + (ts.getTime() - currentTs.getTime()) + " milliseconds than the current server time");
       
      if(!hasPublicKey(pubkey)){
        return constructResponse("No such user registered. needs to register before posting");
      }
        
      getGenAnnouncements().add(a);
        try {saveToFile("genboard");}
        catch (IOException e){
            System.out.println(e.getMessage());
        }
        return constructResponse("General announcement posted");
    }

    public boolean hasPublicKey(PublicKey key) {
	    return _announcementB.containsKey(key);
    }

    public ArrayList<Announcement> getUserAnnouncements(PublicKey pubkey){
        return _announcementB.get(pubkey);
    }

    public ArrayList<Announcement> getGenAnnouncements(){
        return _generalB;
    }

    public Hashtable<PublicKey, ArrayList<Announcement>> getAnnouncements(){
        return _announcementB;
    }

    public Response read(PublicKey pubkey, int number, PublicKey senderKey, Timestamp ts, byte[] signature)
            throws IndexOutOfBoundsException, IllegalArgumentException{
        
      //verify signature
      try {
	Message message = new Message();
	message.appendObject(pubkey);
	message.appendObject(number);
	message.appendObject(senderKey);
	message.appendObject(ts);
	if(!Crypto.verifySignature(senderKey, message.getByteArray(), signature)) {
	  return constructResponse("Signature verification failed");
	}
      } catch(IOException e) {
	  return constructResponse(e.getMessage());
      }

      Timestamp currentTs = new Timestamp(System.currentTimeMillis());
      if(Math.abs(ts.getTime() - currentTs.getTime()) > 5000)
	return constructResponse("Timestamp differs more than " + (ts.getTime() - currentTs.getTime()) + " milliseconds than the current server time");

      if(!hasPublicKey(pubkey) || !hasPublicKey(senderKey)){
        return constructResponse("No such user registered. needs to register before posting");
      }

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
        return readFrom(userAnn, number);
    }

    public Response readGeneral(int number, PublicKey senderKey, Timestamp ts, byte[] signature)
            throws IndexOutOfBoundsException, IllegalArgumentException{
      
      //verify signature
      try {
	Message message = new Message();
	message.appendObject(number);
	message.appendObject(senderKey);
	message.appendObject(ts);
	if(!Crypto.verifySignature(senderKey, message.getByteArray(), signature)) {
	  return constructResponse("Signature verification failed");
	}
      } catch(IOException e) {
	  return constructResponse(e.getMessage());
      }

      Timestamp currentTs = new Timestamp(System.currentTimeMillis());
      if(Math.abs(ts.getTime() - currentTs.getTime()) > 5000)
	return constructResponse("Timestamp differs more than " + (ts.getTime() - currentTs.getTime()) + " milliseconds than the current server time");
      
      
      if(!hasPublicKey(senderKey)){
        return constructResponse("No such user registered. needs to register before posting");
      }

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
        return readFrom(genAnn, number);
    }

    public Response readFrom(ArrayList<Announcement> ann, int number)
            throws IndexOutOfBoundsException, IllegalArgumentException {
        if (number < 0) {
            return constructResponse("Tried to read with a negative number.");
        }
        return number == 0 ? constructResponse("read successful",ann) : constructResponse("read successful",new ArrayList<Announcement>(ann.subList(ann.size() - number, ann.size())));


    }

    public void saveToFile(String path) throws IOException{
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

    public void loadFromFile(String path) throws IOException, ClassNotFoundException{
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
