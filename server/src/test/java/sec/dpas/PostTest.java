package sec.dpas;


import sec.dpas.exceptions.SigningException;

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

/**
 * TODO
 */
public class PostTest
{

    private String _keystorePassword = "keystore";

    @Test
    public void testRegularPost() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

	Message message = new Message();
        long clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0");

	message = new Message();
        clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        long serverNonce = response2.getServerNonce();
	
	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Announcement posted");
    }

    @Test
    public void testInvalidNonce() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

	Message message = new Message();
        long clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0");

	
	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject((long) 1000);
        Response response3 = server.post(pubkey, a, clientNonce, (long) 1000, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Invalid nonce");
    }

    @Test
    public void testWrongPublicKeyPost() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pub2);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pub2, "A1".toCharArray(), null, signature, "1:0");

	message = new Message();
        clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        long serverNonce = response2.getServerNonce();
        
	message = new Message();
        message.appendObject(pub2);
        message.appendObject(a);
	clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        message.appendObject(serverNonce);
        Response response3 = server.post(pub2, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Signature verification failed");

    }

    @Test
    public void testPosterNotRegistered() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

        //Constructing announcement
        Message message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0");

	message = new Message();
        long clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "No such user registered");
        
	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject((long) 0);
        Response response3 = server.post(pubkey, a, clientNonce,(long) 0, Crypto.sign(privkey, message.getByteArray()));
	assertEquals(response3.getStatusCode(), "No such user registered");

    }

    
    @Test
    public void testCorruptedSignature() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pub2);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pub2, "A1".toCharArray(), null, signature, "1:0");

        //Constructing announcement
        message = new Message();
        message.appendObject(pub2);
        message.appendObject("Good Morning".toCharArray());
        message.appendObject(null);
        signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a1 = new Announcement(pub2, "Good Morning".toCharArray(), null, signature, "1:1");
	
	message = new Message();
        clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        long serverNonce = response2.getServerNonce();
        
	message = new Message();
        message.appendObject(pub2);
        message.appendObject(a1);
	clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        message.appendObject(serverNonce);
        Response response3 = server.post(pub2, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response3.getStatusCode(), "Signature verification failed");

    }

    @Test
    public void testInvalidArguments() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        
	Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response.getStatusCode(), "User registered");

        //Constructing announcement
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject("A1".toCharArray());
        message.appendObject(null);
        byte[] signature = Crypto.sign(privkey, message.getByteArray());
        Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, "0:0");

	message = new Message();
        clientNonce = Crypto.generateNonce();
	message.appendObject(pubkey);
        message.appendObject(clientNonce);
        Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        assertEquals(response2.getStatusCode(), "Nonce generated");
        long serverNonce = response2.getServerNonce();
        
	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
	clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        message.appendObject(serverNonce);
        Response response3 = server.post(null, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response4 = server.post(pubkey, null, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response5 = server.post(null, null, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
        Response response6 = server.post(null, null, clientNonce, serverNonce, null);
        Response response7 = server.post(pubkey, a, clientNonce, serverNonce, null);
        Response response8 = server.post(null, a, clientNonce, serverNonce, null);
        Response response9 = server.post(pubkey, null, clientNonce, serverNonce, null);
        assertEquals(response3.getStatusCode(), "Invalid arguments");
        assertEquals(response4.getStatusCode(), "Invalid arguments");
        assertEquals(response5.getStatusCode(), "Invalid arguments");
        assertEquals(response6.getStatusCode(), "Invalid arguments");
        assertEquals(response7.getStatusCode(), "Invalid arguments");
        assertEquals(response8.getStatusCode(), "Invalid arguments");
        assertEquals(response9.getStatusCode(), "Invalid arguments");
    }
}
