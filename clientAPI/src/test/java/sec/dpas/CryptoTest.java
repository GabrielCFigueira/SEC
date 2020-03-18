package sec.dpas;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
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
public class CryptoTest 
{
	@Test(expected = FileNotFoundException.class)
	public void testNonExistentKey() throws FileNotFoundException, IOException {
		Crypto.readPrivateKey("src/resources/nonexistentkey");
	}

	@Test
	public void testReadPrivateKey() throws FileNotFoundException, IOException {
		Crypto.readPrivateKey("src/resources/test.key");
	}

	@Test
	public void testReadPublicKey() throws FileNotFoundException, IOException {
		Crypto.readPublicKey("src/resources/test.key.pub");
	}

/*	@Test
	
	public void testPrivateKey() throws FileNotFoundException, IOException {
		Key key = Crypto.readPrivateKey("src/resources/test.key");
		System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
		assertTrue(original.equals(Base64.getEncoder().encodeToString(key.getEncoded())));

	}*/


	@Test
	public void testPrivateKeyEncryption() throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
		String plaintext = "ThanosDidNothingWrong";
		
		Key key = Crypto.readPrivateKey("src/resources/test.key");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plaintext.getBytes());


		key = Crypto.readPublicKey("src/resources/test.key.pub");
		cipher.init(Cipher.DECRYPT_MODE, key);
		assertTrue(plaintext.equals(new String(cipher.doFinal(ciphertext))));
	}	

}
