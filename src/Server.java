import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Server {
	
	private static byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	private static byte[] ivBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x00, 0x00, 0x01 };
	
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
				
		try {
			SSLSocket sslsocket = handshake();
			
			InputStream inputstream = sslsocket.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
			ArrayList<byte[]> test = new ArrayList<byte[]>();	
			
			OutputStream outputstream = sslsocket.getOutputStream();
            OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
            BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

			String string = null;
			while ((string = bufferedreader.readLine()) != null) {
				byte[] b = (encrypt(string));
				test.add(b); 
				System.out.println(b);
				bufferedwriter.write(new String(b) +'\n');
				bufferedwriter.flush();
				if(test.size() % 5 == 0)
				for(byte[] s: test)
					System.out.println(decrypt(s));
				System.out.flush();
			}
		
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	private static SSLSocket handshake() {
		try {
			SSLServerSocketFactory sslserversocketfactory = 
				(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			
			SSLServerSocket sslserversocket = 
				(SSLServerSocket) sslserversocketfactory.createServerSocket(9999);
			
			String[] enabledCipherSuites = { "SSL_DH_anon_WITH_RC4_128_MD5" };
			sslserversocket.setEnabledCipherSuites(enabledCipherSuites);

			SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();

			return sslsocket;
		
		} catch (Exception exception) {
			exception.printStackTrace();
			return null;
		}
	}
	
	private static byte[] encrypt(String s) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());        
	    byte[] input = s.getBytes();
	    
	    
	    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
	    System.out.println("input : " + new String(input));

	    // encryption pass
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	    ByteArrayInputStream bIn = new ByteArrayInputStream(input);
	    CipherInputStream cIn = new CipherInputStream(bIn, cipher);
	    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

	    int ch;
	    while ((ch = cIn.read()) >= 0) {
	      bOut.write(ch);
	    }

	    byte[] cipherText = bOut.toByteArray();

	    return  (cipherText);

	    
	}
	
	private static String decrypt(byte[] s) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IOException {
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		// decryption pass
		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
	    IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	    CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
	    cOut.write(s);
	    cOut.close();
	    return new String(bOut.toByteArray());
	}
}

