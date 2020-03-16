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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.MessageDigest;

import java.io.FileInputStream;
import java.util.Arrays;
/**
 * TODO!
 *
 */
public class Server implements ClientAPI{

    public Server() {}

    public String sayHello() {
        return "Hello, worldzzzzz!";
    }

    public static void main(String args[]) {
      int registryPort = 1099;
      System.out.println( "Hello World!" );

        try {
            Server obj = new Server();
            //src.hello.Server obj = new src.hello.Server();
            ClientAPI stub = (ClientAPI) UnicastRemoteObject.exportObject(obj, 0);

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
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }



    //TODO implement exceptions, otherwise wont compile
    /*
    public static Key readPrivateKey(String keypath) {
        System.out.println("Reading key from file " + keypath + " ...");
        FileInputStream fis = new FileInputStream(keypath);
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        PrivateKey pub = keyFac.generatePrivate(spec);

        return pub;
    }

    public static Key readPublicKey(String keypath) {
        System.out.println("Reading key from file " + keypath + " ...");
        FileInputStream fis = new FileInputStream(keypath);
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFac = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFac.generatePublic(spec);

        return pub;
    }

    public static byte[] sign(Key key, byte[] message) {

	MessageDigest md = MessageDigest.getInstance("SHA-256");
	md.update(message);
	byte[] digest = md.digest();

	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, key);
	return cipher.doFinal(digest);

    }

    public static boolean verifySignature(Key key, byte[] message, byte[] signature) {

	MessageDigest md = MessageDigest.getInstance("SHA-256");
	md.update(message);
	byte[] digest = md.digest();

	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.DECRYPT_MODE, key);
	return Arrays.equals(digest, cipher.doFinal(digest));

}*/
}
