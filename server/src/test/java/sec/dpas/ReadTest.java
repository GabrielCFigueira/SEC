package sec.dpas;

import sec.dpas.exceptions.NegativeNumberException;
import sec.dpas.exceptions.SigningException;
import sec.dpas.exceptions.InvalidSignatureException;
import sec.dpas.exceptions.InvalidTimestampException;
import sec.dpas.exceptions.AlreadyRegisteredException;

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
public class ReadTest
{
    @Test(expected = NegativeNumberException.class)
    public void testReadNegativeNumber() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        server.read(pubkey, -1);
    }

    @Test
    public void testReadPositiveNumberPrivateKey() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addUserAnnouncement(pubkey, ann1);
        server.addUserAnnouncement(pubkey, ann2);
        server.read(pubkey, 1);
    }

    @Test
    public void testReadAll() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addUserAnnouncement(pubkey, ann1);
        server.addUserAnnouncement(pubkey, ann2);
        server.read(pubkey, 0);
    }

    /*@Test
    public void testReadAll() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
        Announcement ann1 = new Announcement(pubkey, (char) "A1", null);
        Announcement ann2 = new Announcement(pubkey, "A2", null);
        server.addUserAnnouncement(pubkey, ann1);
        server.addUserAnnouncement(pubkey, ann2);
        server.read(pubkey, 0);
    }*/

    @Test(expected = NegativeNumberException.class)
    public void testReadGeneralNegativeNumber() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        server.readGeneral(-1);
    }

    @Test
    public void testReadGeneralPositiveNumberPrivateKey() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addGenAnnouncement(ann1);
        server.addGenAnnouncement(ann2);
        server.readGeneral(1);
    }

    @Test
    public void testReadGeneralAll() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
	PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	Message message = new Message();
	Timestamp ts = new Timestamp(System.currentTimeMillis());

	message.appendObject(pubkey);
	message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addGenAnnouncement(ann1);
        server.addGenAnnouncement(ann2);
        server.readGeneral(0);
    }
}
