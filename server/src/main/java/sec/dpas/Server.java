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
import java.io.FileInputStream;

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
        PublicKey pub = keyFac.generatePrivate(spec);

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
        PrivateKey pub = keyFac.generatePublic(spec);

        return pub;
    }
}