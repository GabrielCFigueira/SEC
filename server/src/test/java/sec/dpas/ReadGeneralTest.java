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
 * ReadGeneralTest
 *
 */
public class ReadGeneralTest {

	private String _keystorePassword = "keystore";

	@Test
	public void testReadGeneralNegativeNumber() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
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
		Response response2 = server.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response2.getStatusCode(), "Nonce generated");
		long serverNonce = response2.getServerNonce();
		
		message = new Message();
		clientNonce = Crypto.generateNonce();
		message.appendObject(-1);
		message.appendObject(pubkey);
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response3 = server.readGeneral(-1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Tried to read with a negative number.");
	}

	@Test
	public void testReadGeneralPositiveNumberPrivateKey() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

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
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, 0);

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
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature, 1);

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
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.readGeneral(1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "read successful");
	}

	@Test
	public void testInvalidNonce() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

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
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, 0);

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
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature, 1);

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
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.readGeneral(1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "Invalid nonce");
	}

	@Test
	public void testReadGeneralAll() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

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
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, 0);

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
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature, 1);

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
		message.appendObject(0);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.readGeneral(0, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "read successful");
	}


	@Test
	public void testReadGeneralCorruptedSignature() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

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
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, 0);

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
		message.appendObject(3000);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response7 = server.readGeneral(1, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response7.getStatusCode(), "Signature verification failed");
	}

	
	@Test
	public void testNullArguments() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");

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
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature, 0);

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
		message.appendObject(1);
		message.appendObject(pubkey);
		clientNonce = Crypto.generateNonce();
		message.appendObject(clientNonce);
		message.appendObject(serverNonce);
		Response response5 = server.readGeneral(1, pubkey, clientNonce, serverNonce, null);
		Response response6 = server.readGeneral(1, null, clientNonce, serverNonce, null);
		Response response7 = server.readGeneral(1, null, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response5.getStatusCode(), "Invalid arguments");
		assertEquals(response6.getStatusCode(), "Invalid arguments");
		assertEquals(response7.getStatusCode(), "Invalid arguments");
	}
}
