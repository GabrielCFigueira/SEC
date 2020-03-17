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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException; 
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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



    public static Key readPrivateKey(String keypath) throws FileNotFoundException, IOException {
        System.out.println("Reading key from file " + keypath + " ...");
        FileInputStream fis = new FileInputStream(keypath);
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
	
	KeyFactory keyFac;
	PrivateKey priv = null;
	try {
		keyFac = KeyFactory.getInstance("RSA");
        	priv = keyFac.generatePrivate(spec);
	} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
		System.err.println("Something really weird happened while reading the private key");
		System.exit(1);
	}
        return priv;
    }

    public static Key readPublicKey(String keypath) throws FileNotFoundException, IOException {
        System.out.println("Reading key from file " + keypath + " ...");
        FileInputStream fis = new FileInputStream(keypath);
        byte[] encoded = new byte[fis.available()];
        fis.read(encoded);
        fis.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
	KeyFactory keyFac;
	PublicKey pub = null;
	try {
		keyFac = KeyFactory.getInstance("RSA");
        	pub = keyFac.generatePublic(spec);
	} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
		System.err.println("Something really weird happened while reading the public key");
		System.exit(1);
	}
        return pub;
    }

    public static byte[] sign(Key key, byte[] message) {

	MessageDigest md = null;
	Cipher cipher = null;
	try {
		md = MessageDigest.getInstance("SHA-256");
		cipher = Cipher.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
		System.err.println("Thanos snapped RSA or SHA-256 out of existance");
		System.exit(1);
	} catch (NoSuchPaddingException e) {
		System.err.println("No padding was provided so God must be messing with the Universe");
		System.exit(1);
	}

	md.update(message);
	byte[] digest = md.digest();
	byte[] signature = null;


	try {	
		cipher.init(Cipher.ENCRYPT_MODE, key);
		signature = cipher.doFinal(digest);
	} catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
		System.err.println(e.getMessage());
		System.exit(1);
	}

	return signature;

    }

    public static boolean verifySignature(Key key, byte[] message, byte[] signature) {

	MessageDigest md = null;
	Cipher cipher = null;
	try {
		md = MessageDigest.getInstance("SHA-256");
		cipher = Cipher.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
		System.err.println("Thanos snapped RSA or SHA-256 out of existance");
		System.exit(1);
	} catch (NoSuchPaddingException e) {
		System.err.println("No padding was provided so God must be messing with the Universe");
		System.exit(1);
	}

	byte[] digest = md.digest(message);
	boolean res = false;
	try {
		cipher.init(Cipher.DECRYPT_MODE, key);
		res = Arrays.equals(digest, cipher.doFinal(signature));
	} catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
		System.err.println(e.getMessage());
		System.exit(1);
	}
	
	return res;
    }
}
