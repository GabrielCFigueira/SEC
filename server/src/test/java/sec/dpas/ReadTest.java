package sec.dpas;

import sec.dpas.exceptions.SigningException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

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
 * TODO
 */
public class ReadTest
{

    private String _keystorePassword = "keystore";

    @Test
    public void testReadNegativeNumber() throws FileNotFoundException, IOException,SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
	PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
  Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	assertTrue(response.getStatusCode().equals("User registered"));
        Response response2 = server.read(pubkey, -1);
        assertTrue(response2.getStatusCode().equals("Tried to read with a negative number."));
    }

    @Test
    public void testReadPositiveNumberPrivateKey() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
	PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	assertTrue(response.getStatusCode().equals("User registered"));

	message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A1".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response2 = server.post(pubkey, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response2.getStatusCode().equals("Announcement posted"));


	message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A2".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response3 = server.post(pubkey, "A2".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response3.getStatusCode().equals("Announcement posted"));

  Response response4 = server.read(pubkey,1);
  assertTrue(response4.getStatusCode().equals("read successful"));
    }

    @Test
    public void testReadAll() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
	PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	assertTrue(response.getStatusCode().equals("User registered"));

	message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A1".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response2 = server.post(pubkey, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response2.getStatusCode().equals("Announcement posted"));


	message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A2".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response3 = server.post(pubkey, "A2".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response3.getStatusCode().equals("Announcement posted"));

  Response response4 = server.read(pubkey,0);
  assertTrue(response4.getStatusCode().equals("read successful"));
    }

  //  @Test
    //public void testReadAll() throws FileNotFoundException, IOException{
      //  Server server = new Server();
        //PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        //server.register(pubkey);
        //Announcement ann1 = new Announcement(pubkey, (char) "A1", null);
        //Announcement ann2 = new Announcement(pubkey, "A2", null);
        //server.addUserAnnouncement(pubkey, ann1);
        //server.addUserAnnouncement(pubkey, ann2);
        //server.read(pubkey, 0);
    //}

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
	assertTrue(response.getStatusCode().equals("User registered"));
  Response response2 = server.readGeneral(-1);
  assertTrue(response2.getStatusCode().equals("Tried to read with a negative number."));
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
	assertTrue(response.getStatusCode().equals("User registered"));

  message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A1".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response2 = server.postGeneral(pubkey, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response2.getStatusCode().equals("General announcement posted"));


	message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A2".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response3 = server.postGeneral(pubkey, "A2".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response3.getStatusCode().equals("General announcement posted"));

	server.post(pubkey, "A2".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));

  Response response4 = server.readGeneral(1);
  assertTrue(response4.getStatusCode().equals("read successful"));
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
	assertTrue(response.getStatusCode().equals("User registered"));

  message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A1".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response2 = server.postGeneral(pubkey, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response2.getStatusCode().equals("General announcement posted"));


	message = new Message();
  message.appendObject(pubkey);
  message.appendObject("A2".toCharArray());
  message.appendObject(null);
  ts = new Timestamp(System.currentTimeMillis());
  message.appendObject(ts);
  Response response3 = server.postGeneral(pubkey, "A2".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
  assertTrue(response3.getStatusCode().equals("General announcement posted"));

	server.post(pubkey, "A2".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));

  Response response4 = server.readGeneral(0);
  assertTrue(response4.getStatusCode().equals("read successful"));
    }
}
