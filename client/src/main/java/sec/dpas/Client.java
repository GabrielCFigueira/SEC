package sec.dpas;


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

import javax.sound.sampled.SourceDataLine;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;


/**
 * Hello world!
 *
 */
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
        String host = (args.length < 1) ? null : args[0];
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

            // verificacao da assinatura da response
            PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
            Message messageReceived = new Message();
            messageReceived.appendObject(response.getStatusCode());
            messageReceived.appendObject(response.getTimestamp());
            
            System.out.println(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()));

            System.out.println("OUTPUT: " + response.getStatusCode());
        }
        catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}
