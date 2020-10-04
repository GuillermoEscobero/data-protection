package main.java.lab1;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;

import java.util.Arrays;

public class SymmetricCipher {
    final int AES_BLOCK_SIZE = 16;

    private SymmetricEncryption s;
    private SymmetricEncryption d;

    // Initialization Vector (fixed)
    public static byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
        (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
        (byte)53, (byte)54};

    /*************************************************************************************/
    /* Constructor method */
    /*************************************************************************************/
    public void SymmetricCipher() {
    }

    private byte[] PKCS5Padding(byte[] plainText, int blockSize) {
        // The padding value is the number remaining bytes to fill the block
        int padding = blockSize - (plainText.length % blockSize);
        if (padding == 0)
            padding = blockSize;

        byte[] paddedText = new byte[plainText.length + padding];

        // Copy the plaintext
        for (int i = 0; i < plainText.length; i++)
            paddedText[i] = plainText[i];

        // Add padding value
        for (int i = plainText.length; i < paddedText.length; i++)
            paddedText[i] = (byte)padding;

        return paddedText;
    }

    private byte[] PKCS5Trimming(byte[] plainText) {
        // The last byte indicates the number of bytes to trim from the
        // plaintext in order to remove the padding
        byte pad = plainText[plainText.length - 1];
        byte[] noPadded = new byte[plainText.length - (int)pad];

        // Copy all bytes but the last ones (padding)
        for (int i = 0; i < noPadded.length; i++)
            noPadded[i] = plainText[i];

        return noPadded;
    }

    /*************************************************************************************/
    /* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
    public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

        if (input == null || byteKey == null)
          return null;

        // Add padding to the input
        input = PKCS5Padding(input, AES_BLOCK_SIZE);

        // Output length will be equal to input length (already padded)
        byte[] ciphertext = new byte[input.length];

        // Initialize encryption engine with AES key passed
        s = new SymmetricEncryption(byteKey);

        // Initialize temporal variables with IV
        byte[] prevBlock = new byte[AES_BLOCK_SIZE];
        byte[] currBlock = new byte[AES_BLOCK_SIZE];
        System.arraycopy(iv, 0, prevBlock, 0, AES_BLOCK_SIZE);
        System.arraycopy(iv, 0, currBlock, 0, AES_BLOCK_SIZE);

        // CBC mode for each block
        for (int i = 0; i < input.length/AES_BLOCK_SIZE; i++) {
            // Get the current block from the input buffer
            System.arraycopy(input, i*AES_BLOCK_SIZE, currBlock, 0, AES_BLOCK_SIZE);

            // XOR operation
            for (int j = 0; j < AES_BLOCK_SIZE; j++)
                currBlock[j] ^= prevBlock[j];

            // Encode the current block with AES
            prevBlock = s.encryptBlock(currBlock);

            // Copy the result to the final buffer
            System.arraycopy(prevBlock, 0, ciphertext, i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }

        return ciphertext;
    }

    /*************************************************************************************/
    /* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
    public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

        if (input == null || byteKey == null)
          return null;

        // Output length will be equal to input length (padding included!)
        // Real output length will be reduced later, when padding is removed
        byte[] plainText = new byte[input.length];

        // Initialize decryption engine with AES key passed
        d = new SymmetricEncryption(byteKey);

        // Initialize temporal variables with IV
        byte[] prevBlock = new byte[AES_BLOCK_SIZE];
        byte[] currBlock = new byte[AES_BLOCK_SIZE];
        byte[] deciphered = new byte[AES_BLOCK_SIZE];
        System.arraycopy(iv, 0, prevBlock, 0, AES_BLOCK_SIZE);
        System.arraycopy(iv, 0, currBlock, 0, AES_BLOCK_SIZE);

        // CBC mode for each block
        for (int i = 0; i < input.length/AES_BLOCK_SIZE; i++) {
            // Get the current block from the input buffer
            System.arraycopy(input, i*AES_BLOCK_SIZE, currBlock, 0, AES_BLOCK_SIZE);

            // Decode the current block with AES
            deciphered = s.decryptBlock(currBlock);

            // XOR operation
            for (int j = 0; j < AES_BLOCK_SIZE; j++)
                deciphered[j] ^= prevBlock[j];

            // Update prevBlock for the next block operation
            System.arraycopy(currBlock, 0, prevBlock, 0, AES_BLOCK_SIZE);

            // Copy the result to the final buffer
            System.arraycopy(deciphered, 0, plainText, i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }

        // Remove padding from cleartext
        plainText = PKCS5Trimming(plainText);

        return plainText;
    }

}
