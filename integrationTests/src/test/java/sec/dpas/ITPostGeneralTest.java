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

import java.util.ArrayList;

import java.lang.Exception;

/**
 * Client/Server Test
 * 
 * ITPostOneClient
 * ITPostTwo
 * ITPostOneDiffClients
 * ITPostTwoDiffClients
 * ITPosterNotRegistered
 * ITPostWrongPublicKey
 * ITPostInvalidNonce
 */
public class ITPostGeneralTest {

    static Registry registry;
    static ServerAPI stub;
    private Server server;

    @Before
    public void init() throws IOException, RemoteException, KeyStoreException, AlreadyBoundException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, NotBoundException {
        int registryPort = 1099;

        server = new Server();
        stub = (ServerAPI) UnicastRemoteObject.exportObject(server, 0);

        registry = LocateRegistry.createRegistry(registryPort);
        registry.bind("ServerAPI", stub);

        stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");
    }

    @After
    public void cleanup() throws RemoteException, NoSuchObjectException, NotBoundException {
        registry.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry, true);
    	server.cleanup();
    }

    @Test
    public void ITPostOneClient() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        this.postGeneral(pubkey, privkey, stub, "A0", null, "0:0");
    }

    @Test
    public void ITPostTwo() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        this.postGeneral(pubkey, privkey, stub, "A0", null, "0:0");

        this.postGeneral(pubkey, privkey, stub, "A1", null, "0:1");
    }

    @Test
    public void ITPostOneDiffClients() throws Exception {        
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        this.postGeneral(pubkey, privkey, stub, "A0", null, "0:0");

        Client client2 = new Client("test1", "testtest1");
        PublicKey pubkey2 = client2.getPublicKey();
        PrivateKey privkey2 = client2.getPrivateKey();

        this.register(pubkey2, privkey2, stub);

        this.postGeneral(pubkey2, privkey2, stub, "B0", null, "1:0");
    }

    @Test
    public void ITPostTwoDiffClients() throws Exception {          
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        this.postGeneral(pubkey, privkey, stub, "A0", null, "0:0");

        this.postGeneral(pubkey, privkey, stub, "A1", null, "0:1");

        Client client2 = new Client("test1", "testtest1");
        PublicKey pubkey2 = client2.getPublicKey();
        PrivateKey privkey2 = client2.getPrivateKey();

        this.register(pubkey2, privkey2, stub);

        this.postGeneral(pubkey2, privkey2, stub, "B0", null, "1:0");

        this.postGeneral(pubkey2, privkey2, stub, "B1", null, "1:1");
    }

    @Test
    public void ITPosterNotRegistered() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        // create
        String body = "A0";
        String id = "0:0";
        ArrayList<Announcement> refs = null;
        Message messageAnn = new Message();
        messageAnn.appendObject(pubkey);
        messageAnn.appendObject(body.toCharArray());
        byte[] signature = Crypto.sign(privkey, messageAnn.getByteArray());
        Announcement ann = new Announcement(pubkey, body.toCharArray(), refs, signature, id);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerification(responseNonce, "No such user registered");

        // create message for post call
        Message messagePost = new Message();
        messagePost.appendObject(pubkey);
        messagePost.appendObject(ann);
        clientNonce = Crypto.generateNonce();
        messagePost.appendObject(clientNonce);
        messagePost.appendObject((long) 0);

        Response responsePost = stub.postGeneral(pubkey, ann, clientNonce, (long) 0, Crypto.sign(privkey, messagePost.getByteArray()));

        this.signatureVerification(responsePost, "No such user registered");
    }

    @Test
    public void ITPostWrongPublicKey() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        Client client2 = new Client("test1", "testtest1");
        PublicKey pubkey2 = client2.getPublicKey();
        PrivateKey privkey2 = client2.getPrivateKey();

        this.register(pubkey, privkey, stub);

        // create
        String body = "A0";
        String id = "0:0";
        ArrayList<Announcement> refs = null;
        Message messageAnn = new Message();
        messageAnn.appendObject(pubkey);
        messageAnn.appendObject(body.toCharArray());
        byte[] signature = Crypto.sign(privkey, messageAnn.getByteArray());
        Announcement ann = new Announcement(pubkey, body.toCharArray(), refs, signature, id);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for post call
        Message messagePost = new Message();
        messagePost.appendObject(pubkey);
        messagePost.appendObject(ann);
        clientNonce = Crypto.generateNonce();
        messagePost.appendObject(clientNonce);
        messagePost.appendObject(serverNonce);

        Response responsePost = stub.postGeneral(pubkey2, ann, clientNonce, serverNonce, Crypto.sign(privkey, messagePost.getByteArray()));

        this.signatureVerification(responsePost, "Signature verification failed");
    }

    @Test
    public void ITPostInvalidNonce() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        // create
        String body = "A0";
        String id = "0:0";
        ArrayList<Announcement> refs = null;
        Message messageAnn = new Message();
        messageAnn.appendObject(pubkey);
        messageAnn.appendObject(body.toCharArray());
        byte[] signature = Crypto.sign(privkey, messageAnn.getByteArray());
        Announcement ann = new Announcement(pubkey, body.toCharArray(), refs, signature, id);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for post call
        Message messagePost = new Message();
        messagePost.appendObject(pubkey);
        messagePost.appendObject(ann);
        clientNonce = Crypto.generateNonce();
        messagePost.appendObject(clientNonce);
        messagePost.appendObject((long) 1);

        Response responsePost = stub.postGeneral(pubkey, ann, clientNonce, (long) 1, Crypto.sign(privkey, messagePost.getByteArray()));

        this.signatureVerification(responsePost, "Invalid nonce");
    }

    @Test
    public void ITPostGeneralBodySizeGreaterThan255() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        String body = "A";
        String bodyRepeated = body.repeat(256);
        String id = "0:0";
        ArrayList<Announcement> refs = null;

        // create
        Message messageAnn = new Message();
        messageAnn.appendObject(pubkey);
        messageAnn.appendObject(bodyRepeated.toCharArray());
        byte[] signature = Crypto.sign(privkey, messageAnn.getByteArray());
        Announcement ann = new Announcement(pubkey, bodyRepeated.toCharArray(), refs, signature, id);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for post call
        Message messagePost = new Message();
        messagePost.appendObject(pubkey);
        messagePost.appendObject(ann);
        clientNonce = Crypto.generateNonce();
        messagePost.appendObject(clientNonce);
        messagePost.appendObject(serverNonce);

        Response responsePost = stub.post(pubkey, ann, clientNonce, serverNonce, Crypto.sign(privkey, messagePost.getByteArray()));

        this.signatureVerification(responsePost, "Invalid arguments");
    }

    @Test
    public void ITPostGeneralBodySize0() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        String body = "";
        String id = "0:0";
        ArrayList<Announcement> refs = null;

        // create
        Message messageAnn = new Message();
        messageAnn.appendObject(pubkey);
        messageAnn.appendObject(body.toCharArray());
        byte[] signature = Crypto.sign(privkey, messageAnn.getByteArray());
        Announcement ann = new Announcement(pubkey, body.toCharArray(), refs, signature, id);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for post call
        Message messagePost = new Message();
        messagePost.appendObject(pubkey);
        messagePost.appendObject(ann);
        clientNonce = Crypto.generateNonce();
        messagePost.appendObject(clientNonce);
        messagePost.appendObject(serverNonce);

        Response responsePost = stub.post(pubkey, ann, clientNonce, serverNonce, Crypto.sign(privkey, messagePost.getByteArray()));

        this.signatureVerification(responsePost, "Invalid arguments");
    }



    //register(Client client)
    //  criar msg
    //  stub.register
    //  signature ver
    public void register(PublicKey pubkey, PrivateKey privkey, ServerAPI stub) throws Exception {
        // create message for register call
        Message messageRegister = new Message();
        messageRegister.appendObject(pubkey);
        long clientNonce = Crypto.generateNonce();
        messageRegister.appendObject(clientNonce);

        Response responseRegister = stub.register(pubkey, clientNonce, Crypto.sign(privkey, messageRegister.getByteArray()));

        this.signatureVerification(responseRegister, "User registered");
    }

    //post(Client client)
    //  criar ann
    //  get server nonce
    //  criar msg
    //  stub.post
    //  signature ver
    public void postGeneral(PublicKey pubkey, PrivateKey privkey, ServerAPI stub, String body, ArrayList<Announcement> refs, String id) throws Exception {
        // create
        Message messageAnn = new Message();
        messageAnn.appendObject(pubkey);
        messageAnn.appendObject(body.toCharArray());
        byte[] signature = Crypto.sign(privkey, messageAnn.getByteArray());
        Announcement ann = new Announcement(pubkey, body.toCharArray(), refs, signature, id);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for post call
        Message messagePost = new Message();
        messagePost.appendObject(pubkey);
        messagePost.appendObject(ann);
        clientNonce = Crypto.generateNonce();
        messagePost.appendObject(clientNonce);
        messagePost.appendObject(serverNonce);

        Response responsePost = stub.postGeneral(pubkey, ann, clientNonce, serverNonce, Crypto.sign(privkey, messagePost.getByteArray()));

        this.signatureVerification(responsePost, "General announcement posted");
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

    public void signatureVerificationNonce(Response response, String statusCode) throws Exception {
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(response.getStatusCode());
        message.appendObject(response.getClientNonce());
        message.appendObject(response.getServerNonce());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), response.getSignature()));
        assertEquals(statusCode, response.getStatusCode());
        assertEquals(null, response.getAnnouncements());
    }
}
