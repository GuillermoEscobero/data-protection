/**
 * @Author: Guillermo Escobero, Alvaro Santos
 * @Date:   04-10-2020
 * @Project: Data Protection Lab
 * @Filename: SimpleSec.java
 * @Last modified by:   Guillermo Escobero, Alvaro Santos
 * @Last modified time: 11-10-2020
 */



package main.java.lab3;

import java.io.File;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.io.Console;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;

import main.java.lab1.SymmetricCipher;
import main.java.lab2.RSALibrary;

public class SimpleSec {
  final int DIGEST_LENGTH = 128;
  private RSALibrary rsaLibrary;
  private SymmetricCipher cipher;

  public void SimpleSec() {
    rsaLibrary = new RSALibrary();
    cipher = new SymmetricCipher();
  }

  private static byte[] concat(byte[] a, byte[] b) {
    int lenA = a.length;
    int lenB = b.length;
    byte[] c = Arrays.copyOf(a, lenA + lenB);
    System.arraycopy(b, 0, c, lenA, lenB);
    return c;
  }

  private void decryptFilePGP(String inputPath, String outputPath, String passphrase) {
    rsaLibrary = new RSALibrary();
    try {
      File inputFile = new File(inputPath);
      File outputFile = new File(outputPath);

      PublicKey publicKey = (PublicKey)rsaLibrary.fileToKey("./public.key");

      ByteArrayInputStream in = new ByteArrayInputStream(decryptFile("./private.key", passphrase.getBytes()));
      ObjectInputStream is = new ObjectInputStream(in);
      PrivateKey privateKey = (PrivateKey)is.readObject();

      // Verify signature
      byte[] fileContent = Files.readAllBytes(inputFile.toPath());
      byte[] signature = new byte[DIGEST_LENGTH];

      byte[] fileNoSignature = new byte[fileContent.length - DIGEST_LENGTH];

      // Trim signature from the end of the file
      System.arraycopy(fileContent, fileContent.length - DIGEST_LENGTH, signature, 0, DIGEST_LENGTH);
      System.arraycopy(fileContent, 0, fileNoSignature, 0, fileContent.length - DIGEST_LENGTH);

      // Verify signature
      if(rsaLibrary.verify(fileNoSignature, signature, publicKey))
        System.out.println("SIGNATURE OK");
      else
        System.out.println("SIGNATURE FAILS");

      // Trim session key from the file
      byte[] sessionKeyEncrypted = new byte[128];
      System.arraycopy(fileNoSignature, fileNoSignature.length - 128, sessionKeyEncrypted, 0, 128);
      byte[] fileNoSessionKey = new byte[fileNoSignature.length - 128];
      System.arraycopy(fileNoSignature, 0, fileNoSessionKey, 0, fileNoSignature.length - 128);

      // Decrypt session key
      byte[] sessionKey = rsaLibrary.decrypt(sessionKeyEncrypted, privateKey);

      // Decrypt file
      fileNoSessionKey = cipher.decryptCBC(fileNoSessionKey, sessionKey);
      Files.write(outputFile.toPath(), fileNoSessionKey);

    } catch(Exception e) {
      e.printStackTrace();
      System.exit(-1);
    }
  }

  private void encryptFilePGP(String inputPath, String outputPath, String passphrase) {
    rsaLibrary = new RSALibrary();
    try {
        byte[] cipherText;
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);

        PublicKey publicKey = (PublicKey)rsaLibrary.fileToKey("./public.key");

        ByteArrayInputStream in = new ByteArrayInputStream(decryptFile("./private.key", passphrase.getBytes()));
        ObjectInputStream is = new ObjectInputStream(in);
        PrivateKey privateKey = (PrivateKey)is.readObject();

        // Create session key for AES
        byte[] sessionKey = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(sessionKey);

        // Encrypt file with AES
        cipherText = encryptFile(inputPath, sessionKey);

        // Encrypt session key with RSA
        // Concatenate file ciphered with AES key ciphered
        cipherText = concat(cipherText, rsaLibrary.encrypt(sessionKey, publicKey));

        // Sign file with RSA
        // Append signature to the ciphertext
        if (cipherText == null) {
          System.out.println("ciphertext null");
        }
        if (privateKey == null) {
          System.out.println("privateKey null");
        }
        cipherText = concat(cipherText, rsaLibrary.sign(cipherText, privateKey));

        Files.write(outputFile.toPath(), cipherText);

    } catch (Exception e) {
        e.printStackTrace();
        System.exit(-1);
    }
  }

  private byte[] encryptFile(String path, byte[] sessionKey) {
    cipher = new SymmetricCipher();

    byte[] cipherText = null;

    try {
      File inputFile = new File(path);

      byte[] fileContent = Files.readAllBytes(inputFile.toPath());
      cipherText = cipher.encryptCBC(fileContent, sessionKey);

    } catch(Exception e) {
      e.printStackTrace();
    }

    return cipherText;
  }

  private byte[] decryptFile(String path, byte[] sessionKey) {
    cipher = new SymmetricCipher();

    byte[] cipherText = null;

    try {
      File inputFile = new File(path);

      byte[] fileContent = Files.readAllBytes(inputFile.toPath());
      cipherText = cipher.decryptCBC(fileContent, sessionKey);

    } catch(Exception e) {
      e.printStackTrace();
    }

    return cipherText;
  }

  private void encryptPath(String path, byte[] sessionKey) {
    cipher = new SymmetricCipher();

    try {
      File inputFile = new File(path);

      byte[] fileContent = Files.readAllBytes(inputFile.toPath());

      Files.write(inputFile.toPath(), cipher.encryptCBC(fileContent, sessionKey));
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  private void generateKeysWithPassphrase(String passphrase) {
    rsaLibrary = new RSALibrary();

    try {
      rsaLibrary.generateKeys();
      encryptPath("./private.key", passphrase.getBytes());

    } catch(Exception e) {
      e.printStackTrace();
    }

/*
    try {
      rsaLibrary.generateKeys();
      cipher = new SymmetricCipher();
      PrivateKey privateKey = (PrivateKey)rsaLibrary.fileToKey("./private.key");

      encryptPath("./private.key", passphrase.getBytes());

      ByteArrayInputStream in = new ByteArrayInputStream(decryptFile("./private.key", passphrase.getBytes()));
      ObjectInputStream is = new ObjectInputStream(in);
      PrivateKey priv2 = (PrivateKey)is.readObject();

      if(privateKey.equals(priv2))
          System.out.println("OK!!!");
      else
        System.out.println("NOT equal");

    } catch(Exception e) {
      e.printStackTrace();
    }
*/
  }

  private String askForPassphrase() {
    Console console = System.console();
    if (console == null) {
      System.out.println("Couldn't get console instance");
      return null;
    }

    String s = new String(console.readPassword("Enter passphrase: "));
    if (s.length() != 16) {
      System.out.println("Passphrase must be 16 bytes long (16 ASCII characters)");
      return null;
    }

    String s2 = new String(console.readPassword("Enter passphrase again: "));

    if (!s.equals(s2)) {
      System.out.println("Passphrase does not match");
      return null;
    }

    return s;
  }

  public static void main(String[] args) {
    if (args.length < 1)
    {
      System.out.println("No arguments");
      return;
    }

    SimpleSec simpleSec = new SimpleSec();
    String s;

    switch(args[0]) {
      case "g":
        //s = simpleSec.askForPassphrase();
        s = "1234567890123456";
        if (s == null)
          return;

        System.out.println("Generating key files...");
        simpleSec.generateKeysWithPassphrase(s);

        break;
      case "e":
        if (args.length < 3)
          return;

        // s = simpleSec.askForPassphrase();
        // if (s == null)
        //   return;
        s = "1234567890123456";

        simpleSec.encryptFilePGP(args[1], args[2], s);
        break;
      case "d":
        if (args.length < 3)
          return;

        // s = simpleSec.askForPassphrase();
        // if (s == null)
        //   return;
        s = "1234567890123456";

        simpleSec.decryptFilePGP(args[1], args[2], s);
        break;
    }
  }
}
