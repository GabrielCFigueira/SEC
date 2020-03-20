package sec.dpas;

import sec.dpas.exceptions.SigningException;
import sec.dpas.exceptions.InvalidSignatureException;
import sec.dpas.exceptions.InvalidTimestampException;


import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.sql.Timestamp;

import java.security.Key;

/**
 * TODO
 */
public class RegisterTest
{
    @Test
    public void testNormalRegister() throws FileNotFoundException, IOException, SigningException, InvalidSignatureException, InvalidTimestampException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
    }


    @Test(expected = InvalidSignatureException.class)
    public void testWrongPublicKeyRegister() throws FileNotFoundException, IOException, SigningException, InvalidSignatureException, InvalidTimestampException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub1");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
    }


    @Test(expected = InvalidSignatureException.class)
    public void testForgedTimestampRegister() throws FileNotFoundException, IOException, SigningException, InvalidSignatureException, InvalidTimestampException, InterruptedException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
	Thread.sleep(10000);
        server.register(pubkey, new Timestamp(System.currentTimeMillis()), signature);
    }


    @Test(expected = InvalidSignatureException.class)
    public void testForgedTimestampRegister2() throws FileNotFoundException, IOException, SigningException, InvalidSignatureException, InvalidTimestampException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
        ts.setTime(ts.getTime() + 10000);
	server.register(pubkey, ts, signature);
    }


    @Test(expected = InvalidTimestampException.class)
    public void testDelayedRegister() throws FileNotFoundException, IOException, SigningException, InvalidSignatureException, InvalidTimestampException, InterruptedException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);
	byte[] signature = Crypto.sign(privkey, message.getByteArray());
	Thread.sleep(10000);
	server.register(pubkey, ts, signature);
    }
}
