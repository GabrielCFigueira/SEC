package sec.dpas;

import sec.dpas.exceptions.SigningException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

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

/**
 * ReadTest
 *
 */
public class ReadTest {

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
	public void testReadNegativeNumber() throws SigningException, IOException {
		
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
		Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response2.getStatusCode(), "Nonce generated");
		long serverNonce = response2.getServerNonce();		

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(-1);
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);

		Response response3 = server.read(pubkey, -1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey,message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Tried to read with a negative number.");
	}

	@Test
	public void testReadPositiveNumberPrivateKey() throws SigningException, IOException {
		
		Message message = new Message();
		long clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);

		Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(),"User registered");

		//constructing Announcement
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
		Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");


		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A2".toCharArray());
		message.appendObject(null);
		signature = Crypto.sign(privkey, message.getByteArray());
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature, "0:1");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response4 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response4.getStatusCode(), "Nonce generated");
		serverNonce = response4.getServerNonce();

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response5 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response5.getStatusCode(), "Announcement posted");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response6 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response6.getStatusCode(), "Nonce generated");
		serverNonce = response6.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "read successful");
	}

	@Test
	public void testInvalidNonce() throws SigningException, IOException {
		
		Message message = new Message();
		long clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);

		Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(),"User registered");

		//constructing Announcement
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
		Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");


		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A2".toCharArray());
		message.appendObject(null);
		signature = Crypto.sign(privkey, message.getByteArray());
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature, "0:1");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response4 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response4.getStatusCode(), "Nonce generated");
		serverNonce = response4.getServerNonce();

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response5 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response5.getStatusCode(), "Announcement posted");

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "Invalid nonce");
	}

	@Test
	public void testReadAll() throws SigningException, IOException {

		Message message = new Message();
		long clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(), "User registered");

		//constructing Announcement
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
		Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");


		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A2".toCharArray());
		message.appendObject(null);
		signature = Crypto.sign(privkey, message.getByteArray());
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature, "0:1");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response4 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response4.getStatusCode(), "Nonce generated");
		serverNonce = response4.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response5 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response5.getStatusCode(), "Announcement posted");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response6 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response6.getStatusCode(), "Nonce generated");
		serverNonce = response6.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(0);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.read(pubkey,0, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "read successful");
	}


	@Test
	public void testCorruptedSignature() throws SigningException, IOException {
		
		Message message = new Message();
		long clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);

		Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(),"User registered");

		//constructing Announcement
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
		Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response6 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response6.getStatusCode(), "Nonce generated");
		serverNonce = response6.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(5);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "Signature verification failed");
	}

	@Test
	public void testNullArguments() throws SigningException, IOException {
		
		Message message = new Message();
		long clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);

		Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(),"User registered");

		//constructing Announcement
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
		Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response4 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response4.getStatusCode(), "Nonce generated");
		serverNonce = response4.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response5 = server.read(pubkey, 1, null, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		Response response6 = server.read(pubkey, 1, pubkey, clientNonce, serverNonce, null);
		Response response7 = server.read(pubkey, 1, null, clientNonce, serverNonce, null);
		assertEquals(response5.getStatusCode(), "Invalid arguments");
		assertEquals(response6.getStatusCode(), "Invalid arguments");
		assertEquals(response7.getStatusCode(), "Invalid arguments");
	}

	@Test
	public void testServerCrash() throws SigningException, IOException {
		
		Message message = new Message();
		long clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);

		Response response = server.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(),"User registered");

		//constructing Announcement
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
		Response response3 = server.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");

		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response6 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response6.getStatusCode(), "Nonce generated");
		serverNonce = response6.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "read successful");

		//crash
		try {
		    server = new Server();
		} catch (Exception e) {
		    fail(e.getMessage());
		}
	
		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		Response response8 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response8.getStatusCode(), "Nonce generated");
		serverNonce = response8.getServerNonce();
		
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response9 = server.read(pubkey, 1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response9.getStatusCode(), "read successful");
	}
}
