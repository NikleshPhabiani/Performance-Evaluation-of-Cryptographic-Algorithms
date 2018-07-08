package org.ncsu.edu;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

public class Cryptotest {
	private static final int AES_KEY_SIZE_128 = 128;
	private static final int AES_KEY_SIZE_256 = 256;
	private static final int HMAC_KEY_SIZE = 256;
	private static final int RSA_KEY_SIZE_1024 = 1024;
	private static final int RSA_KEY_SIZE_4096 = 4096;
	private static final int DIGITAL_SIGNATURE_KEY_SIZE = 4096;
	private double startTime;
	private double endTime;
	private double[] elapsedTimeForEncryption = new double[100];
	private double[] elapsedTimeForDecryption = new double[100];
	private double[] elapsedTimeForRSAEncryption = new double[2];
	private double[] elapsedTimeForRSADecryption = new double[2];
	private double[] elapsedTime = new double[100];
	private double[] elapsedTimeForSignature = new double[100];
	private double[] elapsedTimeForVerification = new double[100];
	private double sumOfElapsedTimeForEncryption = 0;
	private double sumOfElapsedTimeForDecryption = 0;
	private double sumOfElapsedTimeForBlockEncryption = 0;
	private double sumOfElapsedTimeForBlockDecryption = 0;
	private double sumOfElapsedTime = 0;
	private double sumOfElapsedTimeForSignature = 0;
	private double sumOfElapsedTimeForVerification = 0;
	private int iterationNo;
	
	public void performEncryptionDecryptionForAES128(String inputFile) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException, ShortBufferException {
	
	System.out.println("---------------[AES 128]---------------\n\n");
	Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
	for(iterationNo = 0; iterationNo < 100; iterationNo++) {	
		
		//Generating secure random key
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] bytes = new byte[AES_KEY_SIZE_128/8];
		secureRandom.nextBytes(bytes);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(AES_KEY_SIZE_128, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();
		
		//Encryption
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		startTime = System.nanoTime();
		byte[] cipherText = cipher.update(inputFile.getBytes(), 0, inputFile.length());
		endTime = System.nanoTime();
		elapsedTimeForEncryption[iterationNo] = (endTime - startTime) / 1000000000.0;
		System.out.format("[%s] Time elapsed for AES 128 bit encryption: %f\n", iterationNo, elapsedTimeForEncryption[iterationNo]);
		sumOfElapsedTimeForEncryption += elapsedTimeForEncryption[iterationNo];
		AlgorithmParameters algorithmParams = cipher.getParameters();
		byte[] encodedParams = algorithmParams.getEncoded();
		
		//Decryption
		AlgorithmParameters algorithmParamsForDecryption;
		algorithmParamsForDecryption = AlgorithmParameters.getInstance("AES");
		algorithmParamsForDecryption.init(encodedParams);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParamsForDecryption);
		startTime = System.nanoTime();
		byte[] plainText = cipher.update(cipherText,0,cipherText.length);
		endTime = System.nanoTime();
		elapsedTimeForDecryption[iterationNo] = (endTime - startTime) / 1000000000.0;
		System.out.format("[%s] Time elapsed for AES 128 bit decryption: %f\n\n", iterationNo, elapsedTimeForDecryption[iterationNo]);
		sumOfElapsedTimeForDecryption += elapsedTimeForDecryption[iterationNo];
	}
	
	//Calculation of mean time for encryption and decryption
	System.out.format("Mean time for AES 128 bit encryption: %f\n", sumOfElapsedTimeForEncryption/elapsedTimeForEncryption.length);
	System.out.format("Mean time for AES 128 bit decryption: %f\n\n", sumOfElapsedTimeForDecryption/elapsedTimeForDecryption.length);
	sumOfElapsedTimeForEncryption = 0;
	sumOfElapsedTimeForDecryption = 0;
	
	//Calculation of median time for encryption and decryption
	Arrays.sort(elapsedTimeForEncryption);
	Arrays.sort(elapsedTimeForDecryption);
	if(elapsedTimeForEncryption.length % 2 == 0) {
		System.out.format("Median time for AES 128 bit encryption: %f\n",(elapsedTimeForEncryption[elapsedTimeForEncryption.length/2] + elapsedTimeForEncryption[(elapsedTimeForEncryption.length/2)-1])/2);
	}
	else System.out.format("Median time for AES 128 bit encryption: %f\n",elapsedTimeForEncryption[(elapsedTimeForEncryption.length/2)]);
	
	if(elapsedTimeForDecryption.length % 2 == 0) {
		System.out.format("Median time for AES 128 bit decryption: %f\n\n", (elapsedTimeForDecryption[elapsedTimeForDecryption.length/2] + elapsedTimeForDecryption[(elapsedTimeForDecryption.length/2)-1])/2);
	}
	else System.out.format("Median time for AES 128 bit decryption: %f\n\n", elapsedTimeForDecryption[(elapsedTimeForDecryption.length/2)]);
	
}
	
	public void performEncryptionDecryptionForAES256(String inputFile) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		
		System.out.println("---------------[AES 256]---------------\n\n");
		Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
		for(iterationNo = 0; iterationNo < 100; iterationNo++) {	
			
			//Generating secure random key
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			byte[] bytes = new byte[AES_KEY_SIZE_256/8];
			secureRandom.nextBytes(bytes);
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(AES_KEY_SIZE_256, secureRandom);
			SecretKey secretKey = keyGenerator.generateKey();
			
			//Encryption
			
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			startTime = System.nanoTime();
			byte[] cipherText = cipher.update(inputFile.getBytes(),0,inputFile.length());
			endTime = System.nanoTime();
			elapsedTimeForEncryption[iterationNo] = (endTime - startTime)/ 1000000000.0;
			System.out.format("[%s] Time elapsed for AES 256 bit encryption: %f\n", iterationNo, elapsedTimeForEncryption[iterationNo]);
			sumOfElapsedTimeForEncryption += elapsedTimeForEncryption[iterationNo];
			AlgorithmParameters algorithmParams = cipher.getParameters();
			byte[] encodedParams = algorithmParams.getEncoded();
			
			//Decryption
			AlgorithmParameters algorithmParamsForDecryption;
			algorithmParamsForDecryption = AlgorithmParameters.getInstance("AES");
			algorithmParamsForDecryption.init(encodedParams);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParamsForDecryption);
			startTime = System.nanoTime();
			byte[] plainText = cipher.update(cipherText,0,cipherText.length);
			endTime = System.nanoTime();
			elapsedTimeForDecryption[iterationNo] = (endTime - startTime)/ 1000000000.0;
			System.out.format("[%s] Time elapsed for AES 256 bit decryption: %f\n\n", iterationNo, elapsedTimeForDecryption[iterationNo]);
			sumOfElapsedTimeForDecryption += elapsedTimeForDecryption[iterationNo];
		}
		
		//Calculation of mean time for encryption and decryption
		System.out.format("Mean time for AES 256 bit encryption: %f\n", sumOfElapsedTimeForEncryption/elapsedTimeForEncryption.length);
		System.out.format("Mean time for AES 256 bit decryption: %f\n\n", sumOfElapsedTimeForDecryption/elapsedTimeForDecryption.length);
		sumOfElapsedTimeForEncryption = 0;
		sumOfElapsedTimeForDecryption = 0;
		
		//Calculation of median time for encryption and decryption
		Arrays.sort(elapsedTimeForEncryption);
		Arrays.sort(elapsedTimeForDecryption);
		if(elapsedTimeForEncryption.length % 2 == 0) {
			System.out.format("Median time for AES 256 bit encryption: %f\n",(elapsedTimeForEncryption[elapsedTimeForEncryption.length/2] + elapsedTimeForEncryption[(elapsedTimeForEncryption.length/2)-1])/2);
		}
		else System.out.format("Median time for AES 256 bit encryption: %f\n",elapsedTimeForEncryption[(elapsedTimeForEncryption.length/2)]);
		
		if(elapsedTimeForDecryption.length % 2 == 0) {
			System.out.format("Median time for AES 256 bit decryption: %f\n\n", (elapsedTimeForDecryption[elapsedTimeForDecryption.length/2] + elapsedTimeForDecryption[(elapsedTimeForDecryption.length/2)-1])/2);
		}
		else System.out.format("Median time for AES 256 bit decryption: %f\n\n", elapsedTimeForDecryption[(elapsedTimeForDecryption.length/2)]);
		
	}
	
	public void performEncryptionDecryptionForRSA1024(File file) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {
		
		System.out.println("---------------[RSA 1024]---------------\n\n");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		for(iterationNo = 0; iterationNo < 2; iterationNo++) {
			//Generation of key pair
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			byte[] bytes = new byte[RSA_KEY_SIZE_1024/8];
			secureRandom.nextBytes(bytes);
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(RSA_KEY_SIZE_1024, secureRandom);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			//Encryption
			FileInputStream fileInputStream = new FileInputStream(file);
			BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
			byte[] contents = new byte[117];
		    int bytesRead = 0;
		    while ((bytesRead = bufferedInputStream.read(contents)) != -1) {
		    	cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		    	startTime = System.nanoTime();
		    	byte[] cipherText = cipher.doFinal(contents);
		    	endTime = System.nanoTime();
		    	sumOfElapsedTimeForBlockEncryption += (endTime - startTime)/ 1000000000.0;
		    	
            //Decryption
		    	
		    	cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
				startTime = System.nanoTime();
				cipher.doFinal(cipherText);
				endTime = System.nanoTime();
				sumOfElapsedTimeForBlockDecryption += (endTime - startTime)/ 1000000000.0;
		    }
		    bufferedInputStream.close();
		    
			elapsedTimeForRSAEncryption[iterationNo] = sumOfElapsedTimeForBlockEncryption;
			sumOfElapsedTimeForBlockEncryption = 0;
			
			System.out.format("[%s] Time elapsed for RSA 1024 bit encryption: %f\n", iterationNo, elapsedTimeForRSAEncryption[iterationNo]);
			sumOfElapsedTimeForEncryption += elapsedTimeForRSAEncryption[iterationNo];
			
			elapsedTimeForRSADecryption[iterationNo] = sumOfElapsedTimeForBlockDecryption;
			sumOfElapsedTimeForBlockDecryption = 0;
			
			System.out.format("[%s] Time elapsed for RSA 1024 bit decryption: %f\n\n", iterationNo, elapsedTimeForRSADecryption[iterationNo]);
			sumOfElapsedTimeForDecryption += elapsedTimeForRSADecryption[iterationNo];
		}
		
		//Calculation of mean time for encryption and decryption (CHECK THIS AS TIME DISPLAYED WAS DIFFERENT)
		System.out.format("Mean time for RSA 1024 encryption: %f\n", (sumOfElapsedTimeForEncryption/elapsedTimeForRSAEncryption.length));
		System.out.format("Mean time for RSA 1024 decryption: %f\n\n", (sumOfElapsedTimeForDecryption/elapsedTimeForRSADecryption.length));
		sumOfElapsedTimeForEncryption = 0;
		sumOfElapsedTimeForDecryption = 0;
				
		//Calculation of median time for encryption and decryption
		Arrays.sort(elapsedTimeForRSAEncryption);
		Arrays.sort(elapsedTimeForRSADecryption);
		if(elapsedTimeForRSAEncryption.length % 2 == 0) {
			System.out.format("Median time for RSA 1024 encryption: %f\n",(elapsedTimeForRSAEncryption[elapsedTimeForRSAEncryption.length/2] + elapsedTimeForRSAEncryption[(elapsedTimeForRSAEncryption.length/2)-1])/2);
		}
		else System.out.format("Median time for RSA 1024 encryption: %f\n",(elapsedTimeForRSAEncryption[(elapsedTimeForRSAEncryption.length/2)]));
				
		if(elapsedTimeForRSADecryption.length % 2 == 0) {
			System.out.format("Median time for RSA 1024 decryption: %f\n\n", (elapsedTimeForRSADecryption[elapsedTimeForRSADecryption.length/2] + elapsedTimeForRSADecryption[(elapsedTimeForRSADecryption.length/2)-1])/2);
		}
		else System.out.format("Median time for RSA 1024 decryption: %f\n\n", (elapsedTimeForRSADecryption[(elapsedTimeForRSADecryption.length/2)]));
	}
	
	
	public void performEncryptionDecryptionForRSA4096(File file) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		System.out.println("---------------[RSA 4096]---------------\n\n");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		for(iterationNo = 0; iterationNo < 2; iterationNo++) {
			//Generation of key pair
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			byte[] bytes = new byte[RSA_KEY_SIZE_4096/8];
			secureRandom.nextBytes(bytes);
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(RSA_KEY_SIZE_4096, secureRandom);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			FileInputStream fileInputStream = new FileInputStream(file);
			BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
			byte[] contents = new byte[501];
		    int bytesRead = 0;
		    while ((bytesRead = bufferedInputStream.read(contents)) != -1) {
		    	cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		    	startTime = System.nanoTime();
		    	byte[] cipherText = cipher.doFinal(contents);
		    	endTime = System.nanoTime();
		    	sumOfElapsedTimeForBlockEncryption += (endTime - startTime)/ 1000000000.0;
		    	
//		    	Decryption
		    	
		    	cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
				startTime = System.nanoTime();
				cipher.doFinal(cipherText);
				endTime = System.nanoTime();
				sumOfElapsedTimeForBlockDecryption += (endTime - startTime)/ 1000000000.0;
		    }
		    bufferedInputStream.close();
		    
			elapsedTimeForRSAEncryption[iterationNo] = sumOfElapsedTimeForBlockEncryption;
			sumOfElapsedTimeForBlockEncryption = 0;
			
			System.out.format("[%s] Time elapsed for RSA 4096 bit encryption: %f\n", iterationNo, elapsedTimeForRSAEncryption[iterationNo]);
			sumOfElapsedTimeForEncryption += elapsedTimeForRSAEncryption[iterationNo];
			
			elapsedTimeForRSADecryption[iterationNo] = sumOfElapsedTimeForBlockDecryption;
			sumOfElapsedTimeForBlockDecryption = 0;
			
			System.out.format("[%s] Time elapsed for RSA 4096 bit decryption: %f\n\n", iterationNo, elapsedTimeForRSADecryption[iterationNo]);
			sumOfElapsedTimeForDecryption += elapsedTimeForRSADecryption[iterationNo];
		}
		
		//Calculation of mean time for encryption and decryption
		System.out.format("Mean time for RSA 4096 encryption: %f\n", (sumOfElapsedTimeForEncryption/elapsedTimeForRSAEncryption.length));
		System.out.format("Mean time for RSA 4096 decryption: %f\n\n", (sumOfElapsedTimeForDecryption/elapsedTimeForRSADecryption.length));
		sumOfElapsedTimeForEncryption = 0;
		sumOfElapsedTimeForDecryption = 0;
				
		//Calculation of median time for encryption and decryption
		Arrays.sort(elapsedTimeForRSAEncryption);
		Arrays.sort(elapsedTimeForRSADecryption);
		if(elapsedTimeForRSAEncryption.length % 2 == 0) {
			System.out.format("Median time for RSA 4096 encryption: %f\n",(elapsedTimeForRSAEncryption[elapsedTimeForRSAEncryption.length/2] + elapsedTimeForRSAEncryption[(elapsedTimeForRSAEncryption.length/2)-1])/2);
		}
		else System.out.format("Median time for RSA 4096 encryption: %f\n",elapsedTimeForRSAEncryption[(elapsedTimeForRSAEncryption.length/2)]);
				
		if(elapsedTimeForRSADecryption.length % 2 == 0) {
			System.out.format("Median time for RSA 4096 decryption: %f\n\n", (elapsedTimeForRSADecryption[elapsedTimeForRSADecryption.length/2] + elapsedTimeForRSADecryption[(elapsedTimeForRSADecryption.length/2)-1])/2);
		}
		else System.out.format("Median time for RSA 4096 decryption: %f\n\n", elapsedTimeForRSADecryption[(elapsedTimeForRSADecryption.length/2)]);
	}
	
	
	public void performHmacMD5(String inputFile) throws InvalidKeyException, NoSuchAlgorithmException {
	
	System.out.println("---------------[HMAC MD5]---------------\n\n");
	Mac hmacMD5 = Mac.getInstance("HmacMD5");
	
	for(iterationNo = 0; iterationNo < 100; iterationNo++) {
		//Generating secret key
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] bytes = new byte[HMAC_KEY_SIZE/8];
		secureRandom.nextBytes(bytes);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
		keyGenerator.init(HMAC_KEY_SIZE, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();
		
		//Getting instance of Mac object and initializing it with the secret key generated above
		hmacMD5.init(secretKey);
		startTime = System.nanoTime();
		hmacMD5.update(inputFile.getBytes(), 0, inputFile.length());;
		endTime = System.nanoTime();
		elapsedTime[iterationNo] = (endTime - startTime)/ 1000000000.0;
		System.out.format("[%s] Elapsed time for HMAC MD5 operation: %f\n", iterationNo, elapsedTime[iterationNo]);
		sumOfElapsedTime += elapsedTime[iterationNo]; 
	}
	
	//Calculation of mean time for HmacMD5
	System.out.format("Mean time for HMAC MD5: %f\n", sumOfElapsedTime/elapsedTime.length);
	sumOfElapsedTime = 0;
	
	//Calculation of median time for HmacMD5
	Arrays.sort(elapsedTime);
	if(elapsedTime.length % 2 == 0) {
		System.out.format("Median time for HMAC MD5: %f\n\n", (elapsedTime[elapsedTime.length/2] + elapsedTime[(elapsedTime.length/2)-1])/2 );
	}
	else System.out.format("Median time for HMAC MD5: %f\n\n", elapsedTime[elapsedTime.length/2]);	
}
	
	public void performHmacSHA1(String inputFile) throws InvalidKeyException, NoSuchAlgorithmException {
	
	System.out.println("---------------[HMAC SHA1]---------------\n\n");
	Mac hmacSHA1 = Mac.getInstance("HmacSHA1");
	
	for(iterationNo = 0; iterationNo < 100; iterationNo++) {	
		//Generating secret key for HmacSHA1
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] bytes = new byte[HMAC_KEY_SIZE/8];
		secureRandom.nextBytes(bytes);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA1");
		keyGenerator.init(HMAC_KEY_SIZE, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();
		
		//Getting instance of Mac object and initializing it with the secret key generated above
		hmacSHA1.init(secretKey);
		startTime = System.nanoTime();
		hmacSHA1.update(inputFile.getBytes(), 0, inputFile.length());
		endTime = System.nanoTime();
		elapsedTime[iterationNo] = (endTime - startTime)/ 1000000000.0;
		System.out.format("[%s] Elapsed time for HMAC SHA1 operation: %f\n", iterationNo, elapsedTime[iterationNo]);
		sumOfElapsedTime += elapsedTime[iterationNo]; 
	}
	
	//Calculation of mean time for HmacSHA1
	System.out.format("Mean time for HMAC SHA1: %f\n", sumOfElapsedTime/elapsedTime.length);
	sumOfElapsedTime = 0;
	
	//Calculation of median time for HmacSHA1
	Arrays.sort(elapsedTime);
	if(elapsedTime.length % 2 == 0) {
		System.out.format("Median time for HMAC SHA1: %f\n\n", (elapsedTime[elapsedTime.length/2] + elapsedTime[(elapsedTime.length/2)-1])/2 );
	}
	else System.out.format("Median time for HMAC SHA1: %f\n\n", elapsedTime[elapsedTime.length/2]);

}
	
	
	public void performHmacSHA256(String inputFile) throws InvalidKeyException, NoSuchAlgorithmException {
	
	System.out.println("---------------[HMAC SHA256]---------------\n\n");
	Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
	
	for(iterationNo = 0; iterationNo < 100; iterationNo++) {
		//Generating secret key for HmacSHA256
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] bytes = new byte[HMAC_KEY_SIZE/8];
		secureRandom.nextBytes(bytes);
		KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
		keyGenerator.init(HMAC_KEY_SIZE,secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();
		
		//Getting instance of Mac object and initializing it with the secret key generated above
		hmacSHA256.init(secretKey);
		startTime = System.nanoTime();
		hmacSHA256.update(inputFile.getBytes(), 0, inputFile.length());
		endTime = System.nanoTime();
		elapsedTime[iterationNo] = (endTime - startTime)/ 1000000000.0;
		System.out.format("[%s] Elapsed time for HMAC SHA256 operation: %f\n", iterationNo, elapsedTime[iterationNo]);
		sumOfElapsedTime += elapsedTime[iterationNo]; 
	}
	
	//Calculation of mean time for HmacSHA256
	System.out.format("Mean time for HMAC SHA256: %f\n", sumOfElapsedTime/elapsedTime.length);
	sumOfElapsedTime = 0;
		
	//Calculation of median time for HmacSHA256
	Arrays.sort(elapsedTime);
	if(elapsedTime.length % 2 == 0) {
		System.out.format("Median time for HMAC SHA256: %f\n\n", (elapsedTime[elapsedTime.length/2] + elapsedTime[(elapsedTime.length/2)-1])/2 );
	}
	else System.out.format("Median time for HMAC SHA256: %f\n\n", elapsedTime[elapsedTime.length/2]);

}
	
	
	public void performDigitalSignature(String inputFile) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
	
		System.out.println("---------------[Digital Signature]---------------\n\n");
		//Creating an object of Signature class
		Signature signature = Signature.getInstance("SHA256withRSA");
		
		//Generating private and public key pair. private key to be used for signing and public key to be used for verifying
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		byte[] bytes = new byte[DIGITAL_SIGNATURE_KEY_SIZE/8];
		secureRandom.nextBytes(bytes);
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(DIGITAL_SIGNATURE_KEY_SIZE, secureRandom);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
	for(iterationNo = 0; iterationNo < 100; iterationNo++) {
		
//		Initializing the object of signature class
		signature.initSign(keyPair.getPrivate());
		
		//Supplying input file to the signature object and then signing it
		startTime = System.nanoTime();
		signature.update(inputFile.getBytes());
		byte[] signedFile = signature.sign();
		endTime = System.nanoTime();
		elapsedTimeForSignature[iterationNo] = (endTime - startTime)/ 1000000000.0;
		System.out.format("[%s] Time elapsed for signature: %f\n", iterationNo, elapsedTimeForSignature[iterationNo]);
		sumOfElapsedTimeForSignature += elapsedTimeForSignature[iterationNo];
		
		//Initializing the signature object for verification
		signature.initVerify(keyPair.getPublic());
		
		//Supplying input file to the signature object and then verifying it
		startTime = System.nanoTime();
		signature.update(inputFile.getBytes());
		if(signature.verify(signedFile)) { 
			System.out.println("File verified successfully");
			endTime = System.nanoTime();
			elapsedTimeForVerification[iterationNo] = (endTime - startTime)/ 1000000000.0;
			System.out.format("[%s] Time elapsed for verification: %f\n\n", iterationNo, elapsedTimeForVerification[iterationNo]);
			sumOfElapsedTimeForVerification += elapsedTimeForVerification[iterationNo];
		}
		else System.out.println("File not verified successfully");
	}
	
	//Calculation of mean time for signature and verification
	System.out.format("Mean time for signature: %f\n", sumOfElapsedTimeForSignature/elapsedTimeForSignature.length);
	System.out.format("Mean time for verification: %f\n\n", sumOfElapsedTimeForVerification/elapsedTimeForVerification.length);
	sumOfElapsedTimeForSignature = 0;
	sumOfElapsedTimeForVerification = 0;
	
	//Calculation of median time for signature and verification
	Arrays.sort(elapsedTimeForSignature);
	Arrays.sort(elapsedTimeForVerification);
	if(elapsedTimeForSignature.length % 2 == 0)
		System.out.format("Median time for signature: %f\n", (elapsedTimeForSignature[elapsedTimeForSignature.length/2] + elapsedTimeForSignature[(elapsedTimeForSignature.length/2) - 1])/2);
	else System.out.format("Median time for signature: %f\n", elapsedTimeForSignature[elapsedTimeForSignature.length/2]);
	if(elapsedTimeForVerification.length % 2 == 0)
		System.out.format("Median time for verification: %f\n\n", (elapsedTimeForVerification[elapsedTimeForVerification.length/2] + elapsedTimeForVerification[(elapsedTimeForVerification.length/2) - 1])/2);
	else System.out.format("Median time for verification: %f\n\n", elapsedTimeForVerification[elapsedTimeForVerification.length/2]);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException, SignatureException, ShortBufferException {
		
		File file = new File(args[0]);
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];
		fileInputStream.read(data);
		fileInputStream.close();
		String dataAsString = new String(data, "UTF-8");
		
		Cryptotest cryptotest = new Cryptotest();
		cryptotest.performEncryptionDecryptionForAES128(dataAsString);
		cryptotest.performEncryptionDecryptionForAES256(dataAsString);
		cryptotest.performEncryptionDecryptionForRSA1024(file);
		cryptotest.performEncryptionDecryptionForRSA4096(file);
		cryptotest.performHmacMD5(dataAsString);
		cryptotest.performHmacSHA1(dataAsString);
		cryptotest.performHmacSHA256(dataAsString);
		cryptotest.performDigitalSignature(dataAsString);
		
	}

}
