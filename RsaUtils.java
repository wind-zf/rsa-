package org.starscube.api.common.util;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.io.pem.PemObject;
import org.starscube.api.common.Constants;
import org.starscube.api.common.ContextMap;

public class RsaUtils {

	public static final String PEM_PUBLICKEY = "PUBLIC KEY";

	public static final String PEM_PRIVATEKEY = "PRIVATE KEY";

	public static byte[] decryptBASE64(String key) {
		return Base64.decodeBase64(key);
		// return Base64.decode(key);
	}

	public static String encryptBASE64(byte[] bytes) {
		return Base64.encodeBase64String(bytes);
		// return Base64.encode(bytes);
	}

	public static String convertToPemKey(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
		if (publicKey == null && privateKey == null) {
			return null;
		}
		StringWriter stringWriter = new StringWriter();

		try {
			PEMWriter pemWriter = new PEMWriter(stringWriter, "BC");

			if (publicKey != null) {

				pemWriter.writeObject(new PemObject(PEM_PUBLICKEY, publicKey.getEncoded()));
			} else {
				pemWriter.writeObject(new PemObject(PEM_PRIVATEKEY, privateKey.getEncoded()));
			}
			pemWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return stringWriter.toString();
	}

	/**
	 * 用私钥对信息生成数字签名
	 *
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(byte[] data, String privateKey) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		PEMReader reader = new PEMReader(
				new StringReader("-----BEGIN PRIVATE KEY-----\n" + privateKey + "\n-----END PRIVATE KEY-----"),
				new PasswordFinder() {
					@Override
					public char[] getPassword() {
						// TODO Auto-generated method stub
						return "".toCharArray();
					}
				});
		RSAPrivateKey keyPair = (RSAPrivateKey) reader.readObject();
		reader.close();
		byte[] keyBytes = keyPair.getEncoded();
		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);
		return signature.sign();
	}

	/**
	 * 校验数字签名
	 *
	 * @param data
	 *            加密数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
		// 解密由base64编码的公钥
		// byte[] keyBytes = decryptBASE64("-----BEGIN PUBLIC
		// KEY-----\n"+publicKey+"\n-----END PUBLIC KEY-----");
		byte[] keyBytes = decryptBASE64(publicKey);
		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		Signature signature = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);
		// Signature signature = Signature.getInstance("SHA256WithRSA");
		signature.initVerify(pubKey);
		signature.update(data);
		// 验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}

	public static byte[] sign(String data, byte[] privateKey) throws Exception {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey2 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		Signature signature = Signature.getInstance("MD5WithRSA");
		signature.initSign(privateKey2);
		signature.update(data.getBytes());
		return signature.sign();

	}

	public static boolean verify(String data, byte[] publicKey, byte[] signatureResult) {
		try {
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey2 = keyFactory.generatePublic(x509EncodedKeySpec);
			Signature signature = Signature.getInstance("SHA1WithRSA");
			signature.initVerify(publicKey2);
			signature.update(data.getBytes());
			return signature.verify(signatureResult);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	// 后台测试签名的时候 要和前台保持一致，所以需要将结果转换
	public static String bytes2String(byte[] bytes) {
		StringBuilder string = new StringBuilder();
		for (byte b : bytes) {
			String hexString = Integer.toHexString(0x00FF & b);
			string.append(hexString.length() == 1 ? "0" + hexString : hexString);
		}
		return string.toString();
	}

	// 前台的签名结果是将byte 中的一些 负数转换成了正数，
	// 但是后台验证的方法需要的又必须是转换之前的
	public static byte[] hexStringToByteArray(String data) {
		int k = 0;
		byte[] results = new byte[data.length() / 2];
		for (int i = 0; i + 1 < data.length(); i += 2, k++) {
			results[k] = (byte) (Character.digit(data.charAt(i), 16) << 4);
			results[k] += (byte) (Character.digit(data.charAt(i + 1), 16));
		}
		return results;
	}

	public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);
		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 解密<br>
	 * 用私钥解密
	 *
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(String data, String key) throws Exception {
		return decryptByPrivateKey(decryptBASE64(data), key);
	}

	/**
	 * 解密<br>
	 * 用公钥解密
	 *
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);
		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);
		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}

	/**
	 * 加密<br>
	 * 用公钥加密
	 *
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(String data, String key) throws Exception {
		// 对公钥解密
		byte[] keyBytes = decryptBASE64(key);
		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data.getBytes());
	}

	/**
	 * 加密<br>
	 * 用私钥加密
	 *
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);
		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(Constants.KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}

	/**
	 * 取得私钥
	 *
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Key> keyMap) throws Exception {
		Key key = (Key) keyMap.get(Constants.PRIVATE_KEY);
		return encryptBASE64(key.getEncoded());
		// return convertToPemKey(null, (RSAPrivateKey)key);
	}

	/**
	 * 取得公钥
	 *
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Key> keyMap) throws Exception {
		Key key = keyMap.get(Constants.PUBLIC_KEY);
		return encryptBASE64(key.getEncoded());
		// return convertToPemKey((RSAPublicKey)key, null);
	}

	/**
	 * 初始化密钥
	 *
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Key> initKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(Constants.KEY_ALGORITHM);
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		ContextMap.publicKey.setPublicKey((RSAPublicKey) keyPair.getPublic());
		ContextMap.privateKey.setPrivateKey((RSAPrivateKey) keyPair.getPrivate());
		Map<String, Key> keyMap = new HashMap<String, Key>(2);
		keyMap.put(Constants.PUBLIC_KEY, keyPair.getPublic());// 公钥
		keyMap.put(Constants.PRIVATE_KEY, keyPair.getPrivate());// 私钥
		return keyMap;
	}

}
