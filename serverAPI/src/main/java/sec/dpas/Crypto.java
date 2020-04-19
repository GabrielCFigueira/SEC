package sec.dpas;

import sec.dpas.exceptions.SigningException;

/* Java Crypto imports */
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.CertificateException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import java.util.Arrays;

import java.util.UUID;

/**
 * Crypto
 *
 */
public class Crypto {

	public static PrivateKey readPrivateKey(String keystore, String keyname, String keystorePassword, String keyPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
		System.out.println("Reading key from file " + keystore + " ...");
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(keystore), keystorePassword.toCharArray());
		return (PrivateKey) keyStore.getKey(keyname, keyPassword.toCharArray());
	}

	public static PublicKey readPublicKey(String keypath) throws FileNotFoundException, IOException {
		System.out.println("Reading key from file " + keypath + " ...");
		FileInputStream fis = new FileInputStream(keypath);
		byte[] encoded = new byte[fis.available()];
		fis.read(encoded);
		fis.close();

		X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
		KeyFactory keyFac;
		PublicKey pub = null;
		try {
			keyFac = KeyFactory.getInstance("RSA");
			pub = keyFac.generatePublic(spec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.err.println("Something really weird happened while reading the public key");
			System.err.println(e.getMessage());
			System.exit(1);
		}
		return pub;
	}

	public static byte[] sign(Key key, byte[] message) throws SigningException {

		MessageDigest md = null;
		Cipher cipher = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Thanos snapped RSA or SHA-256 out of existance");
			System.exit(1);
		} catch (NoSuchPaddingException e) {
			System.err.println("No padding was provided so God must be messing with the Universe");
			System.exit(1);
		}

		md.update(message);
		byte[] digest = md.digest();
		byte[] signature = null;


		try {
			cipher.init(Cipher.ENCRYPT_MODE, key);
			signature = cipher.doFinal(digest);
		} catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
			throw new SigningException(e.getMessage());
		}

		return signature;

	}

	public static boolean verifySignature(Key key, byte[] message, byte[] signature) {

		MessageDigest md = null;
		Cipher cipher = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
			cipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Thanos snapped RSA or SHA-256 out of existance");
			System.exit(1);
		} catch (NoSuchPaddingException e) {
			System.err.println("No padding was provided so God must be messing with the Universe");
			System.exit(1);
		}

		byte[] digest = md.digest(message);
		boolean res = false;
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			res = Arrays.equals(digest, cipher.doFinal(signature));
		} catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
			System.err.println(e.getMessage() + " when verifying the signature");
			return false;
		}

		return res;
	}

	public static String generateNonce() {
		//SecureRandom random = new SecureRandom();
		//UUID.randomUUID()
		//System.out.println();
		return UUID.randomUUID().toString();
	}
}
