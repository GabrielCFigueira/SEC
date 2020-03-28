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

import java.sql.Timestamp;

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
		Timestamp ts = new Timestamp(System.currentTimeMillis());

		message.appendObject(pubkey);
		message.appendObject(ts);

		Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(), "User registered");

		message = new Message();
		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(-1);
		message.appendObject(pubkey);
		message.appendObject(ts);

		Response response2 = server.readGeneral(-1, pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response2.getStatusCode(), "Tried to read with a negative number.");
	}

	@Test
	public void testReadGeneralPositiveNumberPrivateKey() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
		Message message = new Message();
		Timestamp ts = new Timestamp(System.currentTimeMillis());

		message.appendObject(pubkey);
		message.appendObject(ts);

		Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(), "User registered");

		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A1".toCharArray());
		message.appendObject(null);
		byte[] signature = Crypto.sign(privkey, message.getByteArray());
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature);

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);

		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(ts);
		Response response2 = server.post(pubkey, a, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response2.getStatusCode(), "Announcement posted");


		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A2".toCharArray());
		message.appendObject(null);
		signature = Crypto.sign(privkey, message.getByteArray());
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature);

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);

		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(ts);
		Response response3 = server.post(pubkey, a, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");

		message = new Message();
		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(1);
		message.appendObject(pubkey);
		message.appendObject(ts);

		Response response4 = server.readGeneral(1, pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response4.getStatusCode(), "read successful");
	}

	@Test
	public void testReadGeneralAll() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		Server server = new Server();
		PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
		PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
		Message message = new Message();
		Timestamp ts = new Timestamp(System.currentTimeMillis());

		message.appendObject(pubkey);
		message.appendObject(ts);

		Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response.getStatusCode(), "User registered");

		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A1".toCharArray());
		message.appendObject(null);
		byte[] signature = Crypto.sign(privkey, message.getByteArray());
		Announcement a = new Announcement(pubkey, "A1".toCharArray(), null, signature);

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);

		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(ts);
		Response response2 = server.post(pubkey, a, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response2.getStatusCode(), "Announcement posted");


		//constructing Announcement
		message = new Message();
		message.appendObject(pubkey);
		message.appendObject("A2".toCharArray());
		message.appendObject(null);
		signature = Crypto.sign(privkey, message.getByteArray());
		a = new Announcement(pubkey, "A2".toCharArray(), null, signature);

		message = new Message();
		message.appendObject(pubkey);
		message.appendObject(a);

		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(ts);
		Response response3 = server.post(pubkey, a, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response3.getStatusCode(), "Announcement posted");

		message = new Message();
		ts = new Timestamp(System.currentTimeMillis());
		message.appendObject(0);
		message.appendObject(pubkey);
		message.appendObject(ts);

		Response response4 = server.readGeneral(0, pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
		assertEquals(response4.getStatusCode(), "read successful");
	}
}