package sec.dpas;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.sql.Timestamp;

import java.security.Key;


import sec.dpas.exceptions.SigningException;

/**
 * TODO
 */
public class RegisterTest
{
    @Test
    public void testNormalRegister() throws FileNotFoundException, IOException, SigningException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	assertTrue(response.getStatusCode().equals("User registered"));
    }

    @Test
    public void testDuplicateRegister() throws FileNotFoundException, IOException, SigningException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

	Response response1 = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	Response response2 = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	assertTrue(response1.getStatusCode().equals("User registered"));
	assertTrue(response2.getStatusCode().equals("User was already registered"));
    }

    @Test
    public void testWrongPublicKeyRegister() throws FileNotFoundException, IOException, SigningException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub1");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

	Response response = server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
	assertTrue(response.getStatusCode().equals("Signature verification failed"));
    }


    @Test
    public void testForgedTimestampRegister() throws FileNotFoundException, IOException, SigningException, InterruptedException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
	Thread.sleep(10000);
        Response response = server.register(pubkey, new Timestamp(System.currentTimeMillis()), signature);
	assertTrue(response.getStatusCode().equals("Signature verification failed"));
    }


    @Test
    public void testForgedTimestampRegister2() throws FileNotFoundException, IOException, SigningException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
        ts.setTime(ts.getTime() + 10000);
	Response response = server.register(pubkey, ts, signature);
	assertTrue(response.getStatusCode().equals("Signature verification failed"));
    }


    @Test
    public void testDelayedRegister() throws FileNotFoundException, IOException, SigningException, InterruptedException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
	Thread.sleep(10000);
	Response response = server.register(pubkey, ts, signature);
	assertTrue(response.getStatusCode().matches("Timestamp differs more than.*"));
    }
}
