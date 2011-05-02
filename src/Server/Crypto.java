package Server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
	
	public static byte[] generateAESKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(256); // 192 and 256 bits may not be available

		SecretKey skey = kgen.generateKey();
		return skey.getEncoded();
	}
	
	/**
	 * Encrypts a String via AES
	 * 
	 * @param s
	 *            - to be encrypted
	 * @return - a byte[] of the encrypted string
	 */
	public static byte[] encrypt(String s, byte[] keyBytes) throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		byte[] input = s.getBytes();

		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		// IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES", "BC");

		// encryption pass
		cipher.init(Cipher.ENCRYPT_MODE, key);
		ByteArrayInputStream bIn = new ByteArrayInputStream(input);
		CipherInputStream cIn = new CipherInputStream(bIn, cipher);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		int ch;
		while ((ch = cIn.read()) >= 0) {
			bOut.write(ch);
		}

		byte[] cipherText = bOut.toByteArray();

		return (cipherText);

	}

	/**
	 * Decrypts a String via AES
	 * 
	 * @param s - to be decrypted
	 * @return - a string of the decrypted byte[]
	 */
	public static String decrypt(byte[] s, byte[] keyBytes) {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			// decryption pass
			SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
			cipher.init(Cipher.DECRYPT_MODE, key);
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
			cOut.write(s);
			cOut.close();
			String res = new String(bOut.toByteArray());
			return res;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] rsaDecrypt(byte[] data, String keyFileName) {
		try {
			PrivateKey privKey = readPrivKeyFromFile(keyFileName);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			byte[] cipherData = cipher.doFinal(data);
			return cipherData;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PrivateKey readPrivKeyFromFile(String keyFileName)
			throws IOException {
		InputStream in = new FileInputStream(keyFileName);
		ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(
				in));
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey privKey = fact.generatePrivate(keySpec);
			return privKey;
		} catch (Exception e) {
			throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			oin.close();
		}
	}

	public static byte[] rsaEncrypt(byte[] data, String keyFileName) {
		try {
			PublicKey pubKey = readPubKeyFromFile(keyFileName);
			Cipher cipher;
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] cipherData = cipher.doFinal(data);
			return cipherData;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static PublicKey readPubKeyFromFile(String keyFileName)
			throws IOException {
		InputStream in = new FileInputStream(keyFileName);
		ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(
				in));
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PublicKey pubKey = fact.generatePublic(keySpec);
			return pubKey;
		} catch (Exception e) {
			throw new RuntimeException("Spurious serialisation error", e);
		} finally {
			oin.close();
		}
	}

	public static void generateRSAKeys() throws NoSuchAlgorithmException,
			InvalidKeySpecException, IOException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();

		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
				RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
				RSAPrivateKeySpec.class);

		saveToFile("public.key", pub.getModulus(), pub.getPublicExponent());
		saveToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
	}

	public static void saveToFile(String fileName, BigInteger mod,
			BigInteger exp) throws IOException {
		ObjectOutputStream oout = new ObjectOutputStream(
				new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
			oout.close();
		}
	}
}
