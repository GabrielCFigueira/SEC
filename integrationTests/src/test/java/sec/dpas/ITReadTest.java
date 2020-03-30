package sec.dpas;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.After;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.AlreadyBoundException;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;

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
public class ITReadTest {

    static Registry registry;

    @Before
    public void init() throws IOException, RemoteException, KeyStoreException, AlreadyBoundException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        int registryPort = 1099;

        Server server = new Server();
        ServerAPI stub = (ServerAPI) UnicastRemoteObject.exportObject(server, 0);

        registry = LocateRegistry.createRegistry(registryPort);
        registry.bind("ServerAPI", stub);
    }

    @After
    public void cleanup() throws RemoteException, NoSuchObjectException, NotBoundException {
        registry.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry, true);
    }

    @Test
    public void ITRead() {
/*         try {
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

            assertEquals(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()), true);
            assertEquals(response.getStatusCode(), "User registered");
            assertEquals(response.getAnnouncements(), null);
        } catch (Exception e) {
            System.err.println("@Test Integration Test exception: " + e.toString());
            e.printStackTrace();
        } */
    }

    @Test
    public void ITRead2() {
        
    }
}
