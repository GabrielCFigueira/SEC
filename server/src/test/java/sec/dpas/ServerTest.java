package sec.dpas;

import com.sun.org.apache.bcel.internal.generic.PUSH;
import sec.dpas.exceptions.NegativeNumberException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;

/**
 * TODO
 */
public class ServerTest
{
    @Test(expected = NegativeNumberException.class)
    public void testReadNegativeNumber() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
        server.read(pubkey, -1);
    }

    @Test
    public void testReadPositiveNumberPrivateKey() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addUserAnnouncement(pubkey, ann1);
        server.addUserAnnouncement(pubkey, ann2);
        server.read(pubkey, 1);
    }

    @Test
    public void testReadAll() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
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
    public void testReadGeneralNegativeNumber() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
        server.readGeneral(-1);
    }

    @Test
    public void testReadGeneralPositiveNumberPrivateKey() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addGenAnnouncement(ann1);
        server.addGenAnnouncement(ann2);
        server.readGeneral(1);
    }

    @Test
    public void testReadGeneralAll() throws FileNotFoundException, IOException, NegativeNumberException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        server.register(pubkey);
        Announcement ann1 = new Announcement(pubkey, "A1".toCharArray(), null);
        Announcement ann2 = new Announcement(pubkey, "A2".toCharArray(), null);
        server.addGenAnnouncement(ann1);
        server.addGenAnnouncement(ann2);
        server.readGeneral(0);
    }
}
