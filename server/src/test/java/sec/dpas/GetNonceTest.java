package sec.dpas;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

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
public class GetNonceTest {

    private String _keystorePassword = "keystore";

    @Test
    public void testGetNonce() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

	message = new Message();
	clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
	message.appendObject(clientNonce);
	response = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response.getStatusCode(), "Nonce generated");
    }

    @Test
    public void testRepeatedGetNonce() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

	message = new Message();
	clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
	message.appendObject(clientNonce);
	response = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response.getStatusCode(), "Nonce generated");
	long firstNonce = response.getServerNonce();
	
	message = new Message();
	clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
	message.appendObject(clientNonce);
	response = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response.getStatusCode(), "Nonce generated");
	long secondNonce = response.getServerNonce();

	assertTrue(firstNonce != secondNonce);
	assertTrue(firstNonce != 0);
	assertTrue(secondNonce != 0);
    }

    @Test
    public void testGetNonceBeforeRegistering() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
	message.appendObject(clientNonce);
	Response response = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response.getStatusCode(), "No such user registered");
    }

    @Test
    public void testNullArguments() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

	message = new Message();
	clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
	message.appendObject(clientNonce);
	Response response1 = server.getNonce(null, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	Response response2 = server.getNonce(pubkey, clientNonce, null);
	Response response3 = server.getNonce(null, clientNonce, null);
	assertEquals(response1.getStatusCode(), "Invalid arguments");
	assertEquals(response2.getStatusCode(), "Invalid arguments");
	assertEquals(response3.getStatusCode(), "Invalid arguments");
    }

    @Test
    public void testCorruptedSignature() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

	message = new Message();
	clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
	message.appendObject(Crypto.generateNonce());
	response = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response.getStatusCode(), "Signature verification failed");
    }

    @Test
    public void testWrongPublicKey() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pubkey1 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

	message = new Message();
	clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey1);
	message.appendObject(Crypto.generateNonce());
	response = server.getNonce(pubkey1, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response.getStatusCode(), "Signature verification failed");
    }
}
