import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;

import java.util.Arrays;
import java.io.FileOutputStream;
import java.io.File;

public class SymmetricCipher {
    final int AES_BLOCK_SIZE = 16;

    byte[] byteKey;
    SymmetricEncryption s;
    SymmetricEncryption d;

    // Initialization Vector (fixed)

    static byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
        (byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
        (byte)53, (byte)54};
    static byte[] iv2 = new byte[] {
        (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,

            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54};

    /*************************************************************************************/
    /* Constructor method */
    /*************************************************************************************/
    public void SymmetricCipher() {
    }

    private static void dumpToFile(byte[] content, String file) {
        try {
            OutputStream os = new FileOutputStream(new File(file));
            os.write(content);
            os.flush();
            os.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private byte[] PKCS5Padding(byte[] plainText, int blockSize) {
        int padding = blockSize - (plainText.length % blockSize);
        if (padding == 0)
            padding = blockSize;

        byte[] paddedText = new byte[plainText.length + padding];

        for (int i = 0; i < plainText.length; i++)
            paddedText[i] = plainText[i];

        for (int i = plainText.length; i < paddedText.length; i++)
            paddedText[i] = (byte)padding;

        return paddedText;
    }

    private byte[] PKCS5Trimming(byte[] plainText) {
        byte pad = plainText[plainText.length - 1];
        byte[] noPadded = new byte[plainText.length - (int)pad];

        for (int i = 0; i < noPadded.length; i++)
            noPadded[i] = plainText[i];

        return noPadded;
    }

    /*************************************************************************************/
    /* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
    public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

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

    public static void prettyCryptoPrint(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (i % 16 == 0 && i != 0)
                System.out.println();
            if (i % 8 == 0)
                System.out.print(" ");

            System.out.printf("%02X ", data[i]);
        }
    }

    public static void main(String[] args) throws Exception {
        SymmetricCipher ciph = new SymmetricCipher();
        byte[] imp;

        System.out.println("Encrypting...");
        imp = ciph.encryptCBC(iv2, iv);

        System.out.println("\nCIPHERTEXT");
        prettyCryptoPrint(imp);

        System.out.println("\n\nDecrypting...");
        imp = ciph.decryptCBC(imp, iv);

        System.out.println("\nPLAINTEXT");
        prettyCryptoPrint(imp);

        System.out.print("\n\nBasic test: ");
        for (int i = 0; i < iv2.length; i++) {
            if (iv2[i] != imp[i]) {
                System.out.println("FAIL");
                return;
            }
        }

        System.out.println("Pass");
    }

}
