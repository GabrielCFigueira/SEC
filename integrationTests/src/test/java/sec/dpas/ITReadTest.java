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
 * Client/Server Test: Read
 * 
 * ITReadOne
 * ITReadTwo
 * ITReadOneDiffClient
 * ITReadTwoDiffClient
 * ITReadNegativeNumber
 * ITReadAll
 * ITInvalidNonce
 */
public class ITReadTest {

    static Registry registry;
    static ServerAPI stub;

    @Before
    public void init() throws IOException, RemoteException, KeyStoreException, AlreadyBoundException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, NotBoundException {
        int registryPort = 1099;

        Server server = new Server();
        stub = (ServerAPI) UnicastRemoteObject.exportObject(server, 0);

        registry = LocateRegistry.createRegistry(registryPort);
        registry.bind("ServerAPI", stub);

        stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");
    }

    @After
    public void cleanup() throws RemoteException, NoSuchObjectException, NotBoundException {
        registry.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry, true);
    }

    @Test
    public void ITReadOne() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        anns.add(ann);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(1);
		messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        Response responseRead = stub.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());
    }

    @Test
    public void ITReadTwo() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        anns.add(ann);
        ann = this.post(pubkey, privkey, stub, "A1", null, 1);
        anns.add(ann);


        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(2);
		messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        Response responseRead = stub.read(pubkey, 2, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());
    }

    @Test
    public void ITReadOneDiffClient() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        Client client2 = new Client("test1");
        PublicKey pubkey2 = client2.getPublicKey();
        PrivateKey privkey2 = client2.getPrivateKey();

        this.register(pubkey2, privkey2, stub);

        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        anns.add(ann);
        ArrayList<Announcement> anns2 = new ArrayList<Announcement>();
        ann = this.post(pubkey2, privkey2, stub, "B0", null, 1);
        anns2.add(ann);


        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(1);
		messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        Response responseRead = stub.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());


        // get server nonce
        messageServerNonce = new Message();
        clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        serverNonce = responseNonce.getServerNonce();

        // create message for read call
        messageRead = new Message();
        messageRead.appendObject(pubkey2);
        messageRead.appendObject(1);
        messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        responseRead = stub.read(pubkey2, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());
    }

    @Test
    public void ITReadTwoDiffClient() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        Client client2 = new Client("test1");
        PublicKey pubkey2 = client2.getPublicKey();
        PrivateKey privkey2 = client2.getPrivateKey();

        this.register(pubkey2, privkey2, stub);

        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        anns.add(ann);
        ann = this.post(pubkey, privkey, stub, "A1", null, 1);
        anns.add(ann);
        ArrayList<Announcement> anns2 = new ArrayList<Announcement>();
        ann = this.post(pubkey2, privkey2, stub, "B0", null, 2);
        anns2.add(ann);
        ann = this.post(pubkey2, privkey2, stub, "B1", null, 3);
        anns2.add(ann);


        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(2);
		messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        Response responseRead = stub.read(pubkey, 2, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());


        // get server nonce
        messageServerNonce = new Message();
        clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        serverNonce = responseNonce.getServerNonce();

        // create message for read call
        messageRead = new Message();
        messageRead.appendObject(pubkey2);
        messageRead.appendObject(2);
        messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        responseRead = stub.read(pubkey2, 2, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());
    }

    @Test
    public void ITReadNegativeNumber() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        anns.add(ann);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(-1);
		messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        Response responseRead = stub.read(pubkey, -1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("Tried to read with a negative number.", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());      
    }

    @Test
    public void ITReadAll() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        anns.add(ann);
        ann = this.post(pubkey, privkey, stub, "A1", null, 1);
        anns.add(ann);


        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(0);
		messageRead.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject(serverNonce);

        Response responseRead = stub.read(pubkey, 0, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());
        message.appendObject(responseRead.getAnnouncements());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("read successful", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());
    }

    @Test
    public void ITInvalidNonce() throws Exception {
        Client client = new Client();
        PublicKey pubkey = client.getPublicKey();
        PrivateKey privkey = client.getPrivateKey();

        this.register(pubkey, privkey, stub);

        Announcement ann = this.post(pubkey, privkey, stub, "A0", null, 0);
        ArrayList<Announcement> anns = new ArrayList<Announcement>();
        anns.add(ann);

        // get server nonce


        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        messageRead.appendObject(1);
		messageRead.appendObject(pubkey);
        long clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);
        messageRead.appendObject((long) 1);

        Response responseRead = stub.read(pubkey, 1, pubkey, clientNonce, (long) 1, Crypto.sign(privkey, messageRead.getByteArray()));

        // VERIFICATION
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message message = new Message();
        message.appendObject(responseRead.getStatusCode());
        message.appendObject(responseRead.getClientNonce());

        assertEquals(true, Crypto.verifySignature(serverpubkey, message.getByteArray(), responseRead.getSignature()));
        assertEquals("Invalid nonce", responseRead.getStatusCode());
        //assertEquals(anns, responseRead.getAnnouncements());
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
    public Announcement post(PublicKey pubkey, PrivateKey privkey, ServerAPI stub, String body, ArrayList<Announcement> refs, int id) throws Exception {
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

        this.signatureVerification(responsePost, "Announcement posted");

        return ann;
    }

    //read(Client client)
    //  criar msg
    //  stub.read
    //  signature ver
    //  ann verification
    /*public void read(PublicKey pubkey, PrivateKey privkey, ServerAPI stub, int number) {
        // create message for read call
        Message messageRead = new Message();
        messageRead.appendObject(pubkey);
        long clientNonce = Crypto.generateNonce();
        messageRead.appendObject(clientNonce);

        // get server nonce
        Message messageServerNonce = new Message();
        long clientNonce = Crypto.generateNonce();
        messageServerNonce.appendObject(pubkey);
        messageServerNonce.appendObject(clientNonce);
        Response responseNonce = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, messageServerNonce.getByteArray()));
        
        this.signatureVerificationNonce(responseNonce, "Nonce generated");

        long serverNonce = responseNonce.getServerNonce();

        Response responseRead = stub.read(pubkey, number, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, messageRead.getByteArray()));

        this.signatureVerification(responseRead, "read successful");
    }*/

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
