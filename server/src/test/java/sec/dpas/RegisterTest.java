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
public class RegisterTest {

    private String _keystorePassword = "keystore";

    @Test
    public void testNormalRegister() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
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
    }

    @Test
    public void testDuplicateRegister() throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        Message message = new Message();
	long clientNonce = Crypto.generateNonce();

        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response1 = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response2 = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response1.getStatusCode(), "User registered");
        assertEquals(response2.getStatusCode(), "User was already registered");
    }

    @Test
    public void testWrongPublicKeyRegister() throws FileNotFoundException, IOException, SigningException,
            KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        Message message = new Message();
	long clientNonce = Crypto.generateNonce();

        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "Signature verification failed");
    }

    @Test
    public void testNonceChanged()
            throws FileNotFoundException, IOException, SigningException, KeyStoreException,
            UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        Message message = new Message();
	long clientNonce = Crypto.generateNonce();

        message.appendObject(pubkey);
        message.appendObject(clientNonce);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Response response = server.register(pubkey, Crypto.generateNonce(), signature);
        assertEquals(response.getStatusCode(), "Signature verification failed");
    }

}
