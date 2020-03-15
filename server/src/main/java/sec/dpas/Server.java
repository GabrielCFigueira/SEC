package sec.dpas;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;



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
public class Server implements Hello {

    public Server() {}

    public String sayHello() {
        return "Hello, world!";
    }

    public static void main(String args[]) {

        try {
            src.hello.Server obj = new src.hello.Server();
            Hello stub = (Hello) UnicastRemoteObject.exportObject(obj, 0);

            // Bind the remote object's stub in the registry
            Registry registry = LocateRegistry.getRegistry();
            registry.bind("Hello", stub);

            System.err.println("Server ready");
        } catch (Exception e) {
            System.err.println("Server exception: " + e.toString());
            e.printStackTrace();
        }
    }




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
    
    }
}
