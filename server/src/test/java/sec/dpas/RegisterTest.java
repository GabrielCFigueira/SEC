package sec.dpas;

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

import java.security.Key;

import sec.dpas.exceptions.SigningException;

/**
 * TODO
 */
public class RegisterTest {

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
    public void testNormalRegister() throws SigningException, IOException {

	Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");
    }

    @Test
    public void testDuplicateRegister() throws SigningException, IOException {

        Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response1 = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response2 = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response1.getStatusCode(), "User registered");
        assertEquals(response2.getStatusCode(), "User was already registered");
    }

    @Test
    public void testWrongPublicKeyRegister() throws SigningException, IOException {

        Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pub2);
        message.appendObject(clientNonce);

        Response response = server.register(pub2, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "Signature verification failed");
    }

    @Test
    public void testNonceChanged() throws SigningException, IOException {

        Message message = new Message();
	String clientNonce = Crypto.generateNonce();

        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Response response = server.register(pubkey, Crypto.generateNonce(), signature);
        assertEquals(response.getStatusCode(), "Signature verification failed");
    }

    @Test
    public void testNullArguments() throws SigningException, IOException {

        Message message = new Message();
	String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response1 = server.register(null, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response2 = server.register(pubkey, clientNonce, null);
        Response response3 = server.register(null, clientNonce, null);
        assertEquals(response1.getStatusCode(), "Invalid arguments");
        assertEquals(response2.getStatusCode(), "Invalid arguments");
        assertEquals(response3.getStatusCode(), "Invalid arguments");
    }
}
