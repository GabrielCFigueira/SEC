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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.sql.Timestamp;
import java.util.Hashtable;
import java.util.ArrayList;
import java.util.List;

import sec.dpas.exceptions.NegativeNumberException;
import sec.dpas.exceptions.InvalidSignatureException;
import sec.dpas.exceptions.InvalidTimestampException;

/**
 * TODO!
 *
 */
public class Server implements ServerAPI{

    private Hashtable<PublicKey, ArrayList<Announcement>> _announcementB;
    private ArrayList<Announcement> _generalB;

    public Server() {
        _announcementB = new Hashtable<PublicKey, ArrayList<Announcement>>();
        _generalB = new ArrayList<Announcement>();
    }

    public void register(PublicKey pubkey, Timestamp ts, byte[] signature) throws InvalidSignatureException, InvalidTimestampException{
      
      //verify signature
      try {
	Message message = new Message();
	message.appendObject(pubkey);
	message.appendObject(ts);
	if(!Crypto.verifySignature(pubkey, message.getByteArray(), signature))
	  throw new InvalidSignatureException("Signature verification failed");
      } catch(IOException e) {
	throw new InvalidSignatureException(e.getMessage());
      }

      Timestamp currentTs = new Timestamp(System.currentTimeMillis());
      if(Math.abs(ts.getTime() - currentTs.getTime()) > 5000)
	throw new InvalidTimestampException("Timestamp differs more than " + (ts.getTime() - currentTs.getTime()) + " milliseconds than the current server time");


      _announcementB.put(pubkey,new ArrayList<Announcement>());
    }

    public String post(PublicKey pubkey, char[] message, Announcement[] a){
        getUserAnnouncements(pubkey).add(new Announcement(pubkey,message,a));
        return "posted new announcement on board";
    }

    public String postGeneral(PublicKey pubkey, char[] message, Announcement[] a){
        getGenAnnouncements().add(new Announcement(pubkey,message,a));
        return "posted new announcement on general board";
    }

    public ArrayList<Announcement> getUserAnnouncements(PublicKey pubkey){
        return _announcementB.get(pubkey);
    }

    public ArrayList<Announcement> getGenAnnouncements(){
        return _generalB;
    }

    public void addUserAnnouncement(PublicKey pubkey, Announcement a) {
        getUserAnnouncements(pubkey).add(a);
    }

    public void addGenAnnouncement(Announcement a){
        getGenAnnouncements().add(a);
    }

    public ArrayList<Announcement> read(PublicKey pubkey, int number)
            throws IndexOutOfBoundsException, IllegalArgumentException, NegativeNumberException {
        ArrayList<Announcement> userAnn = getUserAnnouncements(pubkey);
        return readFrom(userAnn, number);
    }

    public ArrayList<Announcement> readGeneral(int number)
            throws IndexOutOfBoundsException, IllegalArgumentException, NegativeNumberException {
        ArrayList<Announcement> genAnn = getGenAnnouncements();
        return readFrom(genAnn, number);
    }

    public ArrayList<Announcement> readFrom(ArrayList<Announcement> ann, int number)
            throws IndexOutOfBoundsException, IllegalArgumentException, NegativeNumberException {
        if (number < 0) {
            throw new NegativeNumberException("Tried to read with a negative number.");
        }
        return number == 0 ? ann : new ArrayList<Announcement>(ann.subList(ann.size() - number, ann.size()));
    }


    public static void main(String args[]) {
        int registryPort = 1099;
        System.out.println( "Hello World!" );

        try {
            Server obj = new Server();
            //src.hello.Server obj = new src.hello.Server();
            ServerAPI stub = (ServerAPI) UnicastRemoteObject.exportObject(obj, 0);

            // Bind the remote object's stub in the registry
            //Registry registry = LocateRegistry.getRegistry();
            Registry registry = LocateRegistry.createRegistry(registryPort); //no garbage collection
            registry.rebind("Hello", stub);
            //Naming.rebind("//localhost:1099/Hello");

            System.err.println("Server ready");
            System.out.println("Awaiting connections");
            System.out.println("Press enter to shutdown");
            System.in.read();
            System.exit(0);
        } catch (IndexOutOfBoundsException e) {
            System.out.println("Exception thrown : " + e);
        } catch (IllegalArgumentException e) {
            System.out.println("Exception thrown : " + e);
        //} catch (NegativeNumberException e) {
            //System.out.println("Exception thrown : " + e);
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }

}
