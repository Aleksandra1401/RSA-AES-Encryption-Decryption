package com.encryptdecrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;

public class EncryptDecrypt extends Application implements EventHandler<ActionEvent> {

	/*
	 * Function to generate and return SecureRandom object for AES key generation.
	 * 
	 * @return secRan cryptographically secure pseudo random number
	 */
	public static SecureRandom getSecRandom() {
		// generate random number
		SecureRandom secRan = null;
		try {
			secRan = SecureRandom.getInstance("DRBG");
			byte[] b = new byte[128];
			secRan.nextBytes(b);
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return secRan;
	}

	/*
	 * Generates SecretKey object using KeyGen generator object that generates AES
	 * key of 256 bytes in size.
	 * 
	 * @param secRan SecureRandom object for key generation
	 * 
	 * @return aesKey randomized SecretKey object
	 */
	public static SecretKey getSymmetricKey(SecureRandom secRan) {
		// generate key
		SecretKey aesKey = null;
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256, secRan); // key size
			aesKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return aesKey;
	}

	/*
	 * Method to generate asymmetric key pair for RSA encryption. After pair is
	 * successfully generated, private key gets stored in one,and public in the
	 * different file. The extension of public key file is ".key" and the extension
	 * for private key file is ".txt"
	 * 
	 * @param fileName base name of the files that will store keys
	 */
	public static void generateKeyPair(String fileName) throws NoSuchAlgorithmException {

		if (fileName.length() == 0 || fileName == null) {
			System.out.println("Please provide valid fileName");
			return;
		}
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(4096); // key size specified here.
		KeyPair pair = keyGen.generateKeyPair();

		// create a directory to store keys if such directory does not exist
		File keyDir = new File("RSA_keys");
		if (!keyDir.exists()) {
			boolean dirCreated = keyDir.mkdirs();
		}

		// create files to store keys
		String path = keyDir.getAbsolutePath() + "\\" + fileName;
		try (FileOutputStream out = new FileOutputStream(path + ".key")) {
			out.write(pair.getPrivate().getEncoded());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try (FileOutputStream out = new FileOutputStream(path + ".txt")) {
			out.write(pair.getPublic().getEncoded());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/*
	 * Generates AES with GCM Cipher object
	 * 
	 * @param aesKey instance of AES key
	 * 
	 * @param iv initialization vector
	 * 
	 * @return cipher Cipher object in ENCRYPT_MODE
	 */
	public static Cipher getAESCipher(SecretKey aesKey, byte[] iv, int mode) {

		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance("AES/GCM/NoPadding");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
			cipher.init(mode, aesKey, parameterSpec);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return cipher;

	}

	/*
	 * Method to encrypt the file. Generates SecureRandom and AES SecretKey objects.
	 * Uses SecureRandom to initialize IV for Cipher object generation. Uses
	 * CipherOutputStream to encrypt using provided encrypt Cipher.
	 * 
	 */
	public static void encrypt(String filePath) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// get the name of the file without extension
		String file = filePath.substring(filePath.lastIndexOf("\\") + 1, filePath.lastIndexOf("."));
		String extension = filePath.substring(filePath.lastIndexOf("."));
		try {
			// create files that store public and private key
			generateKeyPair(file);
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		// generate random number
		SecureRandom secRan = getSecRandom();
		// generate secret key using pseudo random number
		SecretKey aesKey = getSymmetricKey(secRan);
		// generate initialization vector
		byte[] iv = new byte[256 / 8]; // NEVER REUSE THIS IV WITH SAME KEY
		secRan.nextBytes(iv);

		// encrypt aes key
		// 1. get the public key from storage file
		String privatePath = "RSA_keys\\" + file + ".key";
		byte[] bytes = Files.readAllBytes(Paths.get(privatePath));
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		// X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
		// 2. encrypt the aes key
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, pvt);
		byte[] bKey = rsaCipher.doFinal(aesKey.getEncoded());

		// generate cipher
		Cipher aesCipher = getAESCipher(aesKey, iv, Cipher.ENCRYPT_MODE);
		// open streams for reading and writing
		FileInputStream fis = null;
		FileOutputStream fos = null;
		CipherOutputStream cos = null;

		try {
			fis = new FileInputStream(filePath);
			String fileEncryptedPath = filePath.substring(0, filePath.lastIndexOf(".")) + "Encrypted" + extension;
			fos = new FileOutputStream(fileEncryptedPath);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// ENCRYPT
		cos = new CipherOutputStream(fos, aesCipher);
		byte[] b = new byte[8];
		int i;
		try {
			i = fis.read(b);
			// write the encrypted aes key
			fos.write(bKey);
			// write iv
			fos.write(iv);
			// write the bytes of data
			while (i != -1) {
				cos.write(b, 0, i);
				i = fis.read(b);
			}
			// close streams
			cos.flush();
			cos.close();
			fis.close();
			fos.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void decrypt(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		// load RSA private key from the file
		String file = filePath.substring(filePath.lastIndexOf("\\") + 1, filePath.lastIndexOf(".") - 9);
		String extension = filePath.substring(filePath.lastIndexOf("."));
		String fileDecrypted = filePath.substring(0, filePath.lastIndexOf(".") - 9) + "Decrypted" + extension;

		String keyFile = "RSA_keys\\" + file + ".txt";
		byte[] bytes = Files.readAllBytes(Paths.get(keyFile));
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);

		// open streams for reading and writing
		FileOutputStream fos = null;
		CipherOutputStream cos = null;
		// read and decrypt aes key and iv
		try (FileInputStream fis = new FileInputStream(filePath)) {
			SecretKeySpec aesKey = null;

			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.DECRYPT_MODE, pub);
			byte[] b = new byte[512];
			int n = fis.read(b);
			byte[] keyb = rsaCipher.doFinal(b);
			aesKey = new SecretKeySpec(keyb, "AES");

			byte[] iv = new byte[256 / 8];
			fis.read(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// DECRYPT DATA
			Cipher AEScipher = getAESCipher(aesKey, iv, Cipher.DECRYPT_MODE);
			fos = new FileOutputStream(fileDecrypted);
			cos = new CipherOutputStream(fos, AEScipher);
			byte[] bFile = new byte[8];
			int i;
			//
			try {
				i = fis.read(bFile);
				while (i != -1) {
					cos.write(bFile, 0, i);
					i = fis.read(bFile);
				}
				cos.flush();
				cos.close();
				fis.close();
				fos.close();

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	public void start(Stage primaryStage) {
		// GUI
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open Resource File");
		fileChooser.getExtensionFilters().addAll(new ExtensionFilter("Text Files", "*.txt"),
				new ExtensionFilter("Image Files", "*.png", "*.jpg", "*.gif"),
				new ExtensionFilter("Audio Files", "*.wav", "*.mp3", "*.aac"), new ExtensionFilter("All Files", "*.*"));

		Label label1 = new Label("Welcome to RSA AES Encryption!\nChoose file or type absolute path.");
		Button getFile = new Button("Choose File");
		TextField filePath = new TextField();
		Button encryptButton = new Button("Encrypt");
		Button decryptButton = new Button("Decrypt");
		getFile.setOnAction(e -> {
			File selectedFile = fileChooser.showOpenDialog(primaryStage);
			if (selectedFile != null) {
				filePath.setText(selectedFile.getAbsolutePath());
			}
		});

		VBox layout = new VBox();
		layout.getChildren().addAll(label1, getFile, filePath, encryptButton, decryptButton);
		layout.setAlignment(Pos.CENTER);
		Scene scene = new Scene(layout, 300, 250);
		primaryStage.setScene(scene);
		primaryStage.show();

		encryptButton.setOnAction(e -> {
			try {
				encrypt(filePath.getText());
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (InvalidKeySpecException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IllegalBlockSizeException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (BadPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});
		decryptButton.setOnAction(e -> {
			try {
				decrypt(filePath.getText());
			} catch (InvalidKeyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (InvalidKeySpecException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IllegalBlockSizeException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (BadPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});

	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// run the program
		launch(args);

	}

	@Override
	public void handle(ActionEvent arg0) {
		// TODO Auto-generated method stub

	}

}
