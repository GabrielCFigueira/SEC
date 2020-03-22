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
public class PostTest
{

    @Test
    public void testRegularPost() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        PublicKey pub2 = Crypto.readPublicKey("src/resources/test.key.pub1");
	      PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	      Message message = new Message();
	      Timestamp ts = new Timestamp(System.currentTimeMillis());

	       message.appendObject(pubkey);
	       message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        server.post(pubkey, "A1".toCharArray(), null);
    }

    @Test
    public void testRegularGeneralPost() throws FileNotFoundException, IOException, NegativeNumberException, InvalidSignatureException, SigningException, InvalidTimestampException, AlreadyRegisteredException {
        Server server = new Server();
        PublicKey pubkey = Crypto.readPublicKey("src/resources/test.key.pub");
        PublicKey pub2 = Crypto.readPublicKey("src/resources/test.key.pub1");
	      PrivateKey privkey = Crypto.readPrivateKey("src/resources/test.key");
	      Message message = new Message();
	      Timestamp ts = new Timestamp(System.currentTimeMillis());

	       message.appendObject(pubkey);
	       message.appendObject(ts);

        server.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));
        server.postGeneral(pubkey, "A1".toCharArray(), null);
    }

}
