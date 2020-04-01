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

import sec.dpas.exceptions.SigningException;

/**
 * Client/Server Test
 * 
 * ITRegister1Client
 * ITRegister2Clients
 * ITRegisterAlreadyRegistered
 * ITWrongPublicKeyRegister
 * ITNonceChanged
 */
public class ITRegisterTest {

    static Registry registry;
    // FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException
    // FileNotFoundException, IOException, NotBoundException, RemoteException, SigningException
    private Server server;

    @Before
    public void init() throws IOException, RemoteException, KeyStoreException, AlreadyBoundException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        int registryPort = 1099;

        server = new Server();
        ServerAPI stub = (ServerAPI) UnicastRemoteObject.exportObject(server, 0);

        registry = LocateRegistry.createRegistry(registryPort);
        registry.bind("ServerAPI", stub);
    }

    @After
    public void cleanup() throws RemoteException, NoSuchObjectException, NotBoundException {
        registry.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry, true);
	server.cleanup();
    }

    @Test
    public void ITRegister1Client() throws Exception { //, FileNotFoundException, IOException, NotBoundException, RemoteException, SigningException
        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub, "User registered");
    }

    @Test
    public void ITRegister2Clients() throws Exception {
        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub, "User registered");

        Client client2 = new Client("test1", "testtest1");
        PublicKey pubkey2 = client2.getPublicKey();
        PrivateKey privkey2 = client2.getPrivateKey();

        this.register(pubkey2, privkey2, stub, "User registered");
    }

    @Test
    public void ITRegisterAlreadyRegistered() throws Exception {
        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub, "User registered");
        this.register(pubkey, privkey, stub, "User was already registered");
    }

    @Test
    ()
    public void ITWrongPublicKeyRegister() throws Exception {
        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

        Client client = new Client();
        PublicKey Wrongpubkey = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = client.getPrivateKey();

        this.register(Wrongpubkey, privkey, stub, "Signature verification failed");
    }

    @Test
    public void ITNonceChanged() throws Exception {
        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");

        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        // this.register but with double generateNonce
        // create message for register call
        Message messageRegister = new Message();
        messageRegister.appendObject(pubkey);
        long clientNonce = Crypto.generateNonce();
        messageRegister.appendObject(clientNonce);

        Response responseRegister = stub.register(pubkey, Crypto.generateNonce(), Crypto.sign(privkey, messageRegister.getByteArray()));

        this.signatureVerification(responseRegister, "Signature verification failed");
    }



    //register(Client client)
    //  criar msg
    //  stub.register
    //  signature ver
    public void register(PublicKey pubkey, PrivateKey privkey, ServerAPI stub, String statusCode) throws Exception {
        // create message for register call
        Message messageRegister = new Message();
        messageRegister.appendObject(pubkey);
        long clientNonce = Crypto.generateNonce();
        messageRegister.appendObject(clientNonce);

        Response responseRegister = stub.register(pubkey, clientNonce, Crypto.sign(privkey, messageRegister.getByteArray()));

        this.signatureVerification(responseRegister, statusCode);
    }

    public void signatureVerification(Response response, String statusCode) throws Exception {
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(response.getStatusCode());
        message.appendObject(response.getClientNonce());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), response.getSignature()));
        assertEquals(statusCode, response.getStatusCode());
        assertEquals(null, response.getAnnouncements());
    }
}
