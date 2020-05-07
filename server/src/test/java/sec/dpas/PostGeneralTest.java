package sec.dpas;


import sec.dpas.exceptions.SigningException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.security.Key;


/**
 * TODO
 */
public class PostGeneralTest {

    private String _keystorePassword = "keystore";
    private Server server;
    private PublicKey pubkey;
    private PublicKey pub2;
    private PrivateKey privkey;

    @Before
    public void init() throws FileNotFoundException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
	server = new Server();
	pubkey = Crypto.readPublicKey("../resources/test.pub");
	pub2 = Crypto.readPublicKey("../resources/test1.pub");
	privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
    }

    @After
    public void cleanup() {
	    server.cleanup();
    }

    @Test
    public void testRegularGeneralPost() throws SigningException, IOException {

	Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(1);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0", 1);

	message = new Message();
	clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        String serverNonce = response2.getServerNonce();

	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        Response response3 = server.postGeneral(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "General announcement posted");
    }

    @Test
    public void testInvalidNonce() throws SigningException, IOException {

	Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(1);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0", 1);

        String serverNonce = "33333";

	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        Response response3 = server.postGeneral(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Invalid nonce");
    }

    @Test
    public void testWrongPublicKeyGenPost() throws SigningException, IOException {

        Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pub2);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(1);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pub2, "A1".toCharArray(), null, signature, "0:0", 1);

	message = new Message();
	clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        String serverNonce = response2.getServerNonce();

	message = new Message();
        message.appendObject(pub2);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        message.appendObject(serverNonce);
        Response response3 = server.postGeneral(pub2, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Signature verification failed");

    }

    @Test
    public void testGenPosterNotRegistered() throws SigningException, IOException {

        //Constructing announcement
        Message message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(1);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0", 1);

	message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "No such user registered");

	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject("0");
        Response response3 = server.postGeneral(pubkey, a, clientNonce,"0", Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "No such user registered");

    }

    @Test
    public void testGeneralCorruptedSignature() throws SigningException, IOException {

	Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(1);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0", 1);

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("Good Morning".toCharArray());
        signature = Crypto.sign(privkey, message.getByteArray());
	ArrayList<Announcement> array = new ArrayList<Announcement>();
	array.add(a);
        message.appendObject(array);
        message.appendObject(2);
        Announcement a1 = new Announcement(pubkey, "Good Morning".toCharArray(), array, signature, "0:1", 2);

	message = new Message();
	clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        String serverNonce = response2.getServerNonce();

	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        Response response3 = server.postGeneral(pubkey, a1, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Signature verification failed");
    }


    @Test
    public void testNullArguments() throws SigningException, IOException {

	Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(1);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0", 1);

	message = new Message();
	clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        String serverNonce = response2.getServerNonce();

	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        Response response3 = server.postGeneral(null, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response4 = server.postGeneral(pubkey, null, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response5 = server.postGeneral(null, null, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response6 = server.postGeneral(pubkey, a, clientNonce, serverNonce, null);
        Response response7 = server.postGeneral(null, a, clientNonce, serverNonce, null);
        Response response8 = server.postGeneral(pubkey, null, clientNonce, serverNonce, null);
        Response response9 = server.postGeneral(null, null, clientNonce, serverNonce, null);
        assertEquals(response3.getStatusCode(), "Invalid arguments");
        assertEquals(response4.getStatusCode(), "Invalid arguments");
        assertEquals(response5.getStatusCode(), "Invalid arguments");
        assertEquals(response6.getStatusCode(), "Invalid arguments");
        assertEquals(response7.getStatusCode(), "Invalid arguments");
        assertEquals(response8.getStatusCode(), "Invalid arguments");
        assertEquals(response9.getStatusCode(), "Invalid arguments");
    }

    @Test
    public void testInvalidTimeStamp() throws SigningException, IOException {

	Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
	message.appendObject("0:0");
        message.appendObject(0);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0", 0);

	message = new Message();
	clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        String serverNonce = response2.getServerNonce();

	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        Response response3 = server.postGeneral(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Invalid Announcement TimeStamp");
    }

}
