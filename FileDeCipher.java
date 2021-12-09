package final_project;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class contains a set of methods that conform a command line utility 
 * which allows the user to encrypt and decrypt files.
 * @author Daniel Villota
 * @author Camilo Enriquez
 * @author Jose Restrepo
 */
public class FileDeCipher {

	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String SALT = "ABCDEF123456";

	/**
	 * Produces the SHA-1 hash for a given file.
	 * @param file	the file that contains the data to be hashed.
	 * @return a byte array with the correspondent hash. The array length is 20 bytes.
	 */
	public static byte[] hash(File file) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		InputStream fis = new FileInputStream(file);
		byte[] buffer = new byte[8192];
		int bytesRead;
		while ((bytesRead = fis.read(buffer)) != -1) {
			if(bytesRead > 0) digest.update(buffer, 0, bytesRead);
		}
		fis.close();
		return digest.digest();
	}

	/**
	 * Generates an inicialization vector (IV) with an instance of SecureRandom.
	 * @return an instance of IvParameterSpec built with an array of securely generated random bytes.
	 */
	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	/**
	 * Produces a SecretKey object given a password using PBKDF2 as key derivation function 
	 * and AES scheme.
	 * Password length is not checked.
	 * @param password	the password to be used to build the key.
	 * @return an instance of SecretKey. 
	 * This key has a length of 128 bits and it's 
	 * formed after 65536 iterations of PBKDF2, 
	 * its salt is a hardcoded string.
	 */
	public static SecretKey getKeyFromPassword(char[] password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password, SALT.getBytes(), 65536, 128);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		return secret;
	}

	/**
	 * Encrypts a file using a given key. This method writes the result in the given output file.
	 * @param key			the key that will be used in the encryption process. It's an instance of SecretKey.
	 * @param inputFile		the file to encrypt.
	 * @param outputFile	the file where the encrypted data will be stored among it's hash and it's IV.
	 * @see generateKeyFromPassword
	 * @see hash
	 */
	public static void encryptFile(SecretKey key, File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
	NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		IvParameterSpec iv = generateIv();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] hash = hash(inputFile);
		outputStream.write(hash);
		byte[] ivB = iv.getIV();
		outputStream.write(ivB);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}

	/**
	 * Decrypts a file using a given key. This method writes the result in the given output file.
	 * @param key			the key that will be used in the decryption process. It's an instance of SecretKey.
	 * @param inputFile		the file to decrypt.
	 * @param outputFile	the file where the decrypted data will be stored.
	 * @see generateKeyFromPassword
	 * @see hash
	 */
	public static boolean decryptFile(SecretKey key, File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
	NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
	BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);

		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] hash = new byte[20];
		inputStream.read(hash);
		byte[] ivB = new byte[16];
		inputStream.read(ivB);

		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivB));

		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		try {
			byte[] outputBytes = cipher.doFinal();
			if (outputBytes != null) {
				outputStream.write(outputBytes);
			}
		} catch (BadPaddingException | IllegalBlockSizeException e) {
			return false;
		} finally {
			inputStream.close();
			outputStream.close();
		}
		byte[] expectedHash = hash(outputFile);
		for (int i = 0; i < expectedHash.length; i++) {
			if(hash[i] != expectedHash[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Prints a menu that allows the user to interact with the program. 
	 * It provides 2 options: Encryption and decryption of a file.
	 * @param args default parameter for main method. It has no effect on the program.
	 */
	public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, 
	NoSuchAlgorithmException, InvalidAlgorithmParameterException, 
	BadPaddingException, IllegalBlockSizeException, 
	InvalidKeySpecException, IOException {
		Scanner sc = new Scanner(System.in);
		System.out.println("Options:");
		System.out.println("[1] Encrypt File");
		System.out.println("[2] Decrypt File");
		System.out.print("Enter your option: ");
		String opt = sc.nextLine();
		String inputFileName, outputFileName;
		File inputFile, outputFile;
		char[] password;
		switch (opt) {
		case "1":
			System.out.print("Enter the name of the file you want to cipher: ");
			inputFileName = sc.nextLine();
			inputFile = new File(inputFileName);
			System.out.print("Enter the name of the output file: ");
			outputFileName = sc.nextLine();
			outputFile = new File(outputFileName);
			System.out.print("Please enter the password: ");
			password = System.console().readPassword();
			try {
				encryptFile(getKeyFromPassword(password), inputFile, outputFile);
				System.out.println("The message has been ciphered successfully!");
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				sc.close();
			}
			break;
		case "2":
			System.out.print("Enter the name of the file you want to decipher: ");
			inputFileName = sc.nextLine();
			inputFile = new File(inputFileName);
			System.out.print("Enter the name of the output file: ");
			outputFileName = sc.nextLine();
			outputFile = new File(outputFileName);
			System.out.print("Please enter the password: ");
			password = System.console().readPassword();
			try {
				if(decryptFile(getKeyFromPassword(password), inputFile, outputFile)) {
					System.out.println("The message has been deciphered successfully!");
				} else {
					System.out.println("Hashes are different, incorrect password! output file is going to be deleted.");
					outputFile.delete();
				}
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				sc.close();
			}
			break;
		default:
			System.out.println("Please provide a valid option.");
		}
		sc.close();
	}

}
