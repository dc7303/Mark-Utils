package com.codef.io.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 * 작성일: 2019.07.17
 * JAVA 버전: 1.8
 *
 * RSA 암호화 유틸입니다.
 * 키사이즈는 Default로 2048을 사용하고 있습니다.
 * 유틸에서 생성된 키는 각각 인코딩된 String값으로 반환되어 사용됩니다.
 * 사용될 때는 각 키를 디코딩하여 각 키 인스턴스를 생성 후 암호화 또는 복호화에 사용됩니다.
 * 
 * @author choedongcheol
 *
 */
public class RSAUtil {
	
	private static String ENCRYPT_TYPE_RSA = "RSA";
	
	
	/**
	 * 공개키와 개인키 생성
	 * 
	 * @return map을 반환하고 map은 String type의 publicKey와 privateKey를 가지고 있습니다.
	 * @throws NoSuchAlgorithmException
	 */
	public static Map<String, String> genRSAKeysMap() throws NoSuchAlgorithmException {
		// RSA 키쌍을 생성
        KeyPair keyPair = genRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // 공개키로 Base64 인코딩 및 문자열 생성
        byte[] encodedPublicKey = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);

        // 개인키를 Base64 인코딩 및 문자열 생성
        byte[] encodedPrivateKey = privateKey.getEncoded();
        String base64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);
        
        Map<String, String> keysMap = new HashMap<String, String>();
        keysMap.put("publicKey", base64PublicKey);
        keysMap.put("privateKey", base64PrivateKey);
        
        return keysMap;
	}

	/**
	 * Public Key로 RSA 암호화를 수행합니다.
	 * 
	 * @param plainText 암호화할 평문입니다.
	 * @param publicKey 공개키 입니다.
	 * @return 암호화된 데이터 String
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * 
	 */
	public static String encryptRSA(String plainText, String base64PublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
				InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		byte[] bytePublicKey = Base64.getDecoder().decode(base64PublicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(ENCRYPT_TYPE_RSA);
		PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(bytePublicKey));
		
		Cipher cipher = Cipher.getInstance(ENCRYPT_TYPE_RSA);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] bytePlain = cipher.doFinal(plainText.getBytes());
		String encrypted = Base64.getEncoder().encodeToString(bytePlain);

		return encrypted;

	}


	/**
	 * Private Key로 RAS 복호화를 수행합니다.
	 * 
	 * @param encrypted  암호화된 이진데이터를 base64 인코딩한 문자열 입니다.
	 * @param privateKey 복호화를 위한 개인키 입니다.
	 * @return 복호화된 데이터 String
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeySpecException
	 */
	public static String decryptRSA(String encrypted, String base64PrivateKey) 
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeySpecException {

		byte[] bytePrivateKey = Base64.getDecoder().decode(base64PrivateKey);
		KeyFactory keyFactory = KeyFactory.getInstance(ENCRYPT_TYPE_RSA);
		PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(bytePrivateKey));
		
		Cipher cipher = Cipher.getInstance(ENCRYPT_TYPE_RSA);
		byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] bytePlain = cipher.doFinal(byteEncrypted);
		String decrypted = new String(bytePlain, "utf-8");
		
		return decrypted;
	}
	
	

	/**
	 * KeyPair를 생성합니다.
	 * keysize는 2048입니다.
	 * 
	 * @return KeyPair
	 * @throws NoSuchAlgorithmException
	 */
	private static KeyPair genRSAKeyPair() throws NoSuchAlgorithmException {

		SecureRandom secureRandom = new SecureRandom();
		KeyPairGenerator gen;
		gen = KeyPairGenerator.getInstance(ENCRYPT_TYPE_RSA);
		gen.initialize(2048, secureRandom);
		KeyPair keyPair = gen.genKeyPair();

		return keyPair;

	}
	
}
