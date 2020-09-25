import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;


public class RSALibrary {

    // String to hold name of the encryption algorithm.
    private static final String ALGORITHM = "RSA";

    //String to hold the name of the private key file.
    public static final String PRIVATE_KEY_FILE = "./private.key";

    // String to hold name of the public key file.
    public static final String PUBLIC_KEY_FILE = "./public.key";

    /***********************************************************************************/
    /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
    /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
    /* Throws IOException */
    /***********************************************************************************/
    public void generateKeys() throws IOException {

        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(1024, new SecureRandom());

            // Use KeyGen to generate a public and a private key
            KeyPair pair = keyGen.generateKeyPair();
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            // Store the public key in the file PUBLIC_KEY_FILE
            keyToFile(publicKey, PUBLIC_KEY_FILE);

            // Store the private key in the file PRIVATE_KEY_FILE
            keyToFile(privateKey, PRIVATE_KEY_FILE);

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Exception: " + e.getMessage());
            System.exit(-1);
        }
    }

    public void keyToFile(Key key, String file) {
        try {
            FileOutputStream fos = new FileOutputStream(file);
            ObjectOutputStream oos = new ObjectOutputStream(fos);

            oos.writeObject(key);
            oos.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public Key fileToKey(String file) {
        Key key = null;

        try {
            FileInputStream ios = new FileInputStream(file);
            ObjectInputStream ois = new ObjectInputStream(ios);

            key = (Key)ois.readObject();

            ois.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }

        return key;
    }

    /***********************************************************************************/
    /* Encrypts a plaintext using an RSA public key. */
    /* Arguments: the plaintext and the RSA public key */
    /* Returns a byte array with the ciphertext */
    /***********************************************************************************/
    public byte[] encrypt(byte[] plainText, PublicKey key) {

        byte[] cipherText = null;

        if (plainText == null || key == null)
            return null;

        try {
            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // Initialize the cipher object and use it to encrypt the plaintext
            cipher.init(Cipher.ENCRYPT_MODE, key);

            cipherText = cipher.doFinal(plainText);

        } catch (IllegalBlockSizeException i) {
            System.out.println("Message is longer than the key");
        }

        catch (Exception e) {
            e.printStackTrace();
        }

        return cipherText;
    }

    /***********************************************************************************/
    /* Decrypts a ciphertext using an RSA private key. */
    /* Arguments: the ciphertext and the RSA private key */
    /* Returns a byte array with the plaintext */
    /***********************************************************************************/
    public byte[] decrypt(byte[] cipherText, PrivateKey key) {

        byte[] plainText = null;

        if(cipherText == null || key == null)
            return null;

        try {
            // Gets an RSA cipher object
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // Initialize the cipher object and use it to decrypt the ciphertext
            cipher.init(Cipher.DECRYPT_MODE, key);

            plainText = cipher.doFinal(cipherText);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return plainText;
    }

    /***********************************************************************************/
    /* Signs a plaintext using an RSA private key. */
    /* Arguments: the plaintext and the RSA private key */
    /* Returns a byte array with the signature */
    /***********************************************************************************/
    public byte[] sign(byte[] plainText, PrivateKey key) {

        byte[] signedInfo = null;

        try {
            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // Initialize the signature object with the private key
            signature.initSign(key);

            // Set plaintext as the bytes to be signed
            signature.update(plainText);

            // Sign the plaintext and obtain the signature (signedInfo)
            signedInfo = signature.sign();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return signedInfo;
    }

    /***********************************************************************************/
    /* Verifies a signature over a plaintext */
    /* Arguments: the plaintext, the signature to be verified (signed)
    /* and the RSA public key */
    /* Returns TRUE if the signature was verified, false if not */
    /***********************************************************************************/
    public boolean verify(byte[] plainText, byte[] signed, PublicKey key) {

        boolean result = false;

        try {
            // Gets a Signature object
            Signature signature = Signature.getInstance("SHA1withRSA");

            // Initialize the signature oject with the public key
            signature.initVerify(key);

            // Set plaintext as the bytes to be veryfied
            signature.update(plainText);

            // Verify the signature (signed). Store the outcome in the boolean result
            result = signature.verify(signed);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return result;
    }

}
