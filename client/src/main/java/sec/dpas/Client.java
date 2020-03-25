package sec.dpas;

/**
 * Hello world!
 *
 */


import java.io.FileNotFoundException;
import java.io.IOException;

import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import java.sql.SQLOutput;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Hashtable;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;


public class Client
{
    private PrivateKey _privKey;
    private PublicKey _pubkey;
    private final String _keystorePassword = "keystore";

    private Client() throws FileNotFoundException, IOException {
        try {
            _privKey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        } catch(KeyStoreException e) {
            System.out.println("KeyStoreException");
        } catch(UnrecoverableKeyException e) {
            System.out.println("UnrecoverableKeyException");
        } catch(NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");
        } catch(CertificateException e) {
            System.out.println("CertificateException");
        }

        _pubkey = Crypto.readPublicKey("../resources/test.pub");
    }

    private PrivateKey getPrivateKey() throws FileNotFoundException, IOException{ return _privKey; }

    public PublicKey getPublicKey() throws FileNotFoundException, IOException{ return _pubkey; }



    public static void main(String[] args) {
        System.out.println("#####");
        String host = null;//(args.length < 1) ? null : args[0];
        try{
            Client cli = new Client();
            Response rp = new Response("statusCode", new ArrayList<Announcement>(), new Timestamp(System.currentTimeMillis()), null);
            System.out.println(rp.toString());
            ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");


            System.out.println("#####");

            PublicKey pubkey = cli.getPublicKey();
            PrivateKey privkey = cli.getPrivateKey();
            Message message = new Message();
            Timestamp ts = new Timestamp(System.currentTimeMillis());

            message.appendObject(pubkey);
            message.appendObject(ts);

            System.out.println("#####");

            Response response = stub.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));

            System.out.println("OUTPUT: " + response.getStatusCode());
//            Server server = new Server();
//            PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
//            PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
//            Message message = new Message();
//            Timestamp ts = new Timestamp(System.currentTimeMillis());
//
//            message.appendObject(pubkey);
//            message.appendObject(ts);
//
//            Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
//            assertTrue(response.getStatusCode().equals("User registered"));
        }
        catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}
