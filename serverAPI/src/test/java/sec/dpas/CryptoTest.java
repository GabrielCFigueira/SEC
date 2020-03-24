package sec.dpas;

import sec.dpas.exceptions.SigningException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;

/**
 * TODO
 */
public class CryptoTest 
{

	private String _keyStorePassword = "keystore";

	@Test(expected = IOException.class)
	public void testNonExistentKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		Crypto.readPrivateKey("../resources/nonexistent.store", "key", "bom", "dia");
	}

	@Test(expected = IOException.class)
	public void testWrongKeyStorePassword() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		Crypto.readPrivateKey("../resources/key.store", "test", "wrong", "testtest");
	}

	@Test(expected = UnrecoverableKeyException.class)
	public void testWrongKeyPassword() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "wrong");
	}

	@Test
	public void testNonExistentKey() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		Key key = Crypto.readPrivateKey("../resources/key.store", "nonexistent", _keyStorePassword, "something");
		assertTrue(key == null);
	}

	@Test
	public void testReadPrivateKey() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		Key key = Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "testtest");
		assertTrue(key != null);
	}

	@Test
	public void testReadPublicKey() throws FileNotFoundException, IOException {
		Crypto.readPublicKey("../resources/test.pub");
	}


	@Test
	public void testPrivateKeyEncryption() throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String plaintext = "ThanosDidNothingWrong";
		
		Key key = Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "testtest");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plaintext.getBytes());


		key = Crypto.readPublicKey("../resources/test.pub");
		cipher.init(Cipher.DECRYPT_MODE, key);
		assertTrue(plaintext.equals(new String(cipher.doFinal(ciphertext))));
	}

		
	@Test
	public void testPublicKeyEncryption() throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String plaintext = "Jet fuel cant melt steel beams";
		
		Key key = Crypto.readPublicKey("../resources/test.pub");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] ciphertext = cipher.doFinal(plaintext.getBytes());


		key = Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "testtest");
		cipher.init(Cipher.DECRYPT_MODE, key);
		assertTrue(plaintext.equals(new String(cipher.doFinal(ciphertext))));
	}	

	@Test
	public void testSigning() throws FileNotFoundException, IOException, SigningException , KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		String plaintext = "Every day, we stray further from God";
		Key key = Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "testtest");

		byte[] signature = Crypto.sign(key, plaintext.getBytes());

		key = Crypto.readPublicKey("../resources/test.pub");
		assertTrue(Crypto.verifySignature(key, plaintext.getBytes(), signature));
	}

	@Test
	public void testInvalidSigningDifferentMessage() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		String plaintext = "Sauron was ok I guess";
		String differentPlaintext = "Peace was never an option";
		Key key = Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "testtest");

		byte[] signature = Crypto.sign(key, plaintext.getBytes());

		key = Crypto.readPublicKey("../resources/test.pub");
		assertFalse(Crypto.verifySignature(key, differentPlaintext.getBytes(), signature));
	}

	@Test
	public void testInvalidSigningDifferentKeys() throws FileNotFoundException, IOException, SigningException, KeyStoreException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
		String plaintext = "Only the dead know peace from this evil";

		Key key = Crypto.readPrivateKey("../resources/key.store", "test", _keyStorePassword, "testtest");

		byte[] signature = Crypto.sign(key, plaintext.getBytes());

		key = Crypto.readPublicKey("../resources/test1.pub");
		assertFalse(Crypto.verifySignature(key, plaintext.getBytes(), signature));
	}
}
