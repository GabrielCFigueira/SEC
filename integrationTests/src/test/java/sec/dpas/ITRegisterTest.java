package sec.dpas;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.After;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.Naming;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.Timestamp;

import java.lang.Exception;

/**
 * Client/Server Test
 */
public class ITRegisterTest {

    static Registry registry;

    @Before
    public void init() {
        int registryPort = 1099;
        try {
            Server server = new Server();
            ServerAPI stub = (ServerAPI) UnicastRemoteObject.exportObject(server, 0);

            registry = LocateRegistry.createRegistry(registryPort);
            registry.bind("ServerAPI", stub);
        } catch (Exception e) {
            System.err.println("@Before Integration Test exception: " + e.toString());
            e.printStackTrace();
        }
    }

    @After
    public void cleanup() {
        try {
            registry.unbind("ServerAPI");
            UnicastRemoteObject.unexportObject(registry, true);
        } catch (Exception e) {
            System.err.println("@After Integration Test exception: " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void ITRegister1Client() {
        try {
            // init Client and ServerAPI stub
            Client client = new Client();
            ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

            // get Keys
            PublicKey pubkey = client.getPublicKey();
            PrivateKey privkey = client.getPrivateKey();

            // Create Message, for call to the ServerAPI
            Message message = new Message();
            message.appendObject(pubkey);
            Timestamp ts = new Timestamp(System.currentTimeMillis());
            message.appendObject(ts);
    
            // Call function from ServerAPI
            Response response = stub.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
    
            // Response signature verification
            PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

            Message messageReceived = new Message();
            messageReceived.appendObject(response.getStatusCode());
            messageReceived.appendObject(response.getTimestamp());

            assertEquals(true, Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()));
            assertEquals("User registered", response.getStatusCode());
            assertEquals(null, response.getAnnouncements());
        } catch (Exception e) { // FileNotFoundException, IOException, NotBoundException, RemoteException, SigningException
            System.err.println("@Test Integration Test exception: " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void ITRegister2Clients() {

    }

    @Test
    public void ITRegisterAlreadyRegistered() {
        try {
            // init Client and ServerAPI stub
            Client client = new Client();
            ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

            // get Keys
            PublicKey pubkey = client.getPublicKey();
            PrivateKey privkey = client.getPrivateKey();

            // Create Message, for call to the ServerAPI
            Message message = new Message();
            message.appendObject(pubkey);
            Timestamp ts = new Timestamp(System.currentTimeMillis());
            message.appendObject(ts);
    
            // Call function from ServerAPI
            Response response = stub.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
            Response response2 = stub.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
    
            // Response signature verification
            PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

            Message messageReceived = new Message();
            messageReceived.appendObject(response.getStatusCode());
            messageReceived.appendObject(response.getTimestamp());

            Message messageReceived2 = new Message();
            messageReceived2.appendObject(response2.getStatusCode());
            messageReceived2.appendObject(response2.getTimestamp());

            assertEquals(true, Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()));
            assertEquals("User registered", response.getStatusCode());
            assertEquals(null, response.getAnnouncements());
            assertEquals(true, Crypto.verifySignature(serverpubkey, messageReceived2.getByteArray(), response2.getSignature()));
            assertEquals("User was already registered", response2.getStatusCode());
            assertEquals(null, response2.getAnnouncements());
        } catch (Exception e) {
            System.err.println("@Test Integration Test exception: " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void ITWrongPublicKeyRegister() {
        try {
            // init Client and ServerAPI stub
            Client client = new Client();
            ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

            // get Keys
            PublicKey pubkey = Crypto.readPublicKey("../resources/test1.pub");
            PrivateKey privkey = client.getPrivateKey();

            // Create Message, for call to the ServerAPI
            Message message = new Message();
            message.appendObject(pubkey);
            Timestamp ts = new Timestamp(System.currentTimeMillis());
            message.appendObject(ts);

            Response response = stub.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));

            // Response signature verification
            PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

            Message messageReceived = new Message();
            messageReceived.appendObject(response.getStatusCode());
            messageReceived.appendObject(response.getTimestamp());

            assertEquals(true, Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()));
            assertEquals("Signature verification failed", response.getStatusCode());
            assertEquals(null, response.getAnnouncements());
        } catch (Exception e) {
            System.err.println("@Test Integration Test exception: " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void ITForgedTimestampRegister() { // ITregisterWrongNounceTest in the future
        
    }

    @Test
    public void ITForgedTimestampRegister2() { // ITregisterWrongNounceTest in the future
        
    }

    @Test
    public void ITDelayedRegister() { // ITregisterWrongNounceTest in the future
        
    }
}
