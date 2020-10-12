/**
 * @Author: Guillermo Escobero, Alvaro Santos
 * @Date:   04-10-2020
 * @Project: Data Protection Lab
 * @Filename: SimpleSec.java
 * @Last modified time: 12-10-2020
 */



package main.java.lab3;

import java.io.File;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import java.util.Arrays;
import java.io.Console;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ByteArrayInputStream;
import java.io.StreamCorruptedException;
import java.nio.file.NoSuchFileException;

import main.java.lab1.SymmetricCipher;
import main.java.lab2.RSALibrary;

public class SimpleSec {
  final int DIGEST_LENGTH = 128; // Size of signature in bytes (1024-bits RSA key)
  private RSALibrary rsaLibrary;
  private SymmetricCipher cipher;

  public void SimpleSec() {
    rsaLibrary = new RSALibrary();
    cipher = new SymmetricCipher();
  }

  /* Concatenates B array to A array */
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

      PublicKey publicKey = (PublicKey)rsaLibrary.fileToKey(RSALibrary.PUBLIC_KEY_FILE);

      ByteArrayInputStream in = new ByteArrayInputStream(decryptFile(RSALibrary.PRIVATE_KEY_FILE, passphrase.getBytes()));
      ObjectInputStream is = new ObjectInputStream(in);
      PrivateKey privateKey = (PrivateKey)is.readObject();
      is.close();
      in.close();

      // Verify signature
      byte[] fileContent = Files.readAllBytes(inputFile.toPath());
      byte[] signature = new byte[DIGEST_LENGTH];

      byte[] fileNoSignature = new byte[fileContent.length - DIGEST_LENGTH];

      // Trim signature from the end of the file
      System.arraycopy(fileContent, fileContent.length - DIGEST_LENGTH, signature, 0, DIGEST_LENGTH);
      System.arraycopy(fileContent, 0, fileNoSignature, 0, fileContent.length - DIGEST_LENGTH);

      // Verify signature
      if(!rsaLibrary.verify(fileNoSignature, signature, publicKey)) {
        System.err.println("Error: signature not correct");
        System.exit(-1);
      }

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

    } catch(StreamCorruptedException e) {
      System.err.println("Error: Key not found or bad formatted");
      System.exit(-1);
    } catch(NegativeArraySizeException e) {
      System.err.println("Error: Input file bad formatted");
      System.exit(-1);
    } catch(NullPointerException e) {
      System.err.println("Error: Key not found or bad formatted");
      System.exit(-1);
    } catch(BadPaddingException e) {
      System.err.println("Error: Key not correct");
      System.exit(-1);
    } catch(NoSuchFileException e) {
      System.err.println("Error: Key or input file not found");
      System.exit(-1);
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

        PublicKey publicKey = (PublicKey)rsaLibrary.fileToKey(RSALibrary.PUBLIC_KEY_FILE);

        ByteArrayInputStream in = new ByteArrayInputStream(decryptFile(RSALibrary.PRIVATE_KEY_FILE, passphrase.getBytes()));
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
        cipherText = concat(cipherText, rsaLibrary.sign(cipherText, privateKey));

        Files.write(outputFile.toPath(), cipherText);

      } catch(StreamCorruptedException e) {
        System.err.println("Error: Key not found or bad formatted");
        System.exit(-1);
      } catch(NoSuchFileException e) {
        System.err.println("Error: Key or input file not found");
        System.exit(-1);
      } catch(NullPointerException e) {
        System.err.println("Error: Key not found or bad formatted");
        System.exit(-1);
      } catch(Exception e) {
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
      return null;
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
      return null;
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
      System.err.println("Error: failed when encrypting " + path);
      System.exit(-1);
    }
  }

  private void generateKeysWithPassphrase(String passphrase) {
    rsaLibrary = new RSALibrary();

    try {
      rsaLibrary.generateKeys();
      encryptPath(RSALibrary.PRIVATE_KEY_FILE, passphrase.getBytes());

    } catch(Exception e) {
      System.err.println("Error: failed when generating keys");
      System.exit(-1);
    }
  }

  private String askForPassphrase() {
    Console console = System.console();
    if (console == null) {
      System.err.println("Error: Couldn't get console instance");
      return null;
    }

    String s = new String(console.readPassword("Enter passphrase: "));
    if (s.length() != 16) {
      System.err.println("Passphrase must be 16 bytes long (16 ASCII characters)");
      return null;
    }

    String s2 = new String(console.readPassword("Enter passphrase again: "));
    if (!s.equals(s2)) {
      System.err.println("Passphrase does not match");
      return null;
    }

    return s;
  }

  public static void main(String[] args) {
    if (args.length < 1)
    {
      System.err.println("Usage: simpleSec option [sourceFile destinationFile]");
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
        System.out.println("Keys generated on " + RSALibrary.PUBLIC_KEY_FILE + " and " + RSALibrary.PRIVATE_KEY_FILE);

        break;
      case "e":
        if (args.length < 3)
        {
          System.err.println("Usage: simpleSec e sourceFile destinationFile");
          return;
        }

        // s = simpleSec.askForPassphrase();
        // if (s == null)
        //   return;
        s = "1234567890123456";

        simpleSec.encryptFilePGP(args[1], args[2], s);
        break;
      case "d":
        if (args.length < 3)
        {
          System.err.println("Usage: simpleSec d sourceFile destinationFile");
          return;
        }

        // s = simpleSec.askForPassphrase();
        // if (s == null)
        //   return;
        s = "1234567890123456";

        simpleSec.decryptFilePGP(args[1], args[2], s);
        break;
    }
  }
}
