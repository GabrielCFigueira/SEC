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
    }

    @Test
    public void testWrongPublicKeyPost() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
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
         Response response2 = server.post(pub2, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
         assertTrue(response2.getStatusCode().equals("Signature verification failed"));

    }

    @Test
    public void testPosterNotRegistered() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        Message message = new Message();
	      Timestamp ts = new Timestamp(System.currentTimeMillis());

       	message.appendObject(pubkey);
       	message.appendObject("A1".toCharArray());
        message.appendObject(null);
        message.appendObject(ts);
         Response response2 = server.post(pubkey, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
         System.out.println(response2.getStatusCode());
         assertTrue(response2.getStatusCode().equals("No such user registered. needs to register before posting"));

    }

    @Test
    public void testRegularGeneralPost() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
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
    }

    @Test
    public void testWrongPublicKeyGenPost() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
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
         Response response2 = server.postGeneral(pub2, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
         assertTrue(response2.getStatusCode().equals("Signature verification failed"));

    }

    @Test
    public void testGenPosterNotRegistered() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("../resources/test.pub");
        PublicKey pub2 = Crypto.readPublicKey("../resources/test1.pub");
        PrivateKey privkey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        Message message = new Message();
	      Timestamp ts = new Timestamp(System.currentTimeMillis());

       	message.appendObject(pubkey);
       	message.appendObject("A1".toCharArray());
        message.appendObject(null);
        message.appendObject(ts);
         Response response2 = server.postGeneral(pubkey, "A1".toCharArray(), null, ts, Crypto.sign(privkey, message.getByteArray()));
         System.out.println(response2.getStatusCode());
         assertTrue(response2.getStatusCode().equals("No such user registered. needs to register before posting"));

    }

}
