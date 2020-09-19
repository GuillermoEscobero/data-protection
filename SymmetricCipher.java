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

	private byte[] PKCS5Padding(byte[] plainText, int blockSize) {
		int padding = blockSize - (plainText.length % blockSize);
		if (padding == 0)
			padding = blockSize;

		System.out.println("Adding padding: " + padding);
		byte[] paddedText = new byte[plainText.length + padding];

		for (int i = 0; i < plainText.length; i++)
			paddedText[i] = plainText[i];

		for (int i = plainText.length; i < paddedText.length; i++)
			paddedText[i] = (byte)padding;

		return paddedText;
	}

	private byte[] PKCS5Trimming(byte[] plainText) {
		byte padding = plainText[plainText.length - 1];
		byte[] noPadded = new byte[plainText.length - (int)padding];

		for (int i = 0; i < noPadded.length; i++)
			noPadded[i] = plainText[i];

		return noPadded;
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

		input = PKCS5Padding(input, AES_BLOCK_SIZE);

		int block_number = input.length / AES_BLOCK_SIZE;
		byte[] ciphertext = new byte[block_number * AES_BLOCK_SIZE];

		s = new SymmetricEncryption(byteKey);

		byte pad;

		byte[] prevBlock = new byte[AES_BLOCK_SIZE];
		byte[] currBlock = new byte[AES_BLOCK_SIZE];

		System.arraycopy(iv, 0, prevBlock, 0, prevBlock.length);
		System.arraycopy(iv, 0, currBlock, 0, currBlock.length);

		// BLOQUES COMPLETOS
		for (int i = 0; i < block_number; i++) {
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				currBlock[j] = input[(i * AES_BLOCK_SIZE) + j];
			}
			//XOR
			for (int k = 0; k < AES_BLOCK_SIZE; k++) {
				currBlock[k] ^= prevBlock[k];
			}

			prevBlock = s.encryptBlock(currBlock);
			System.arraycopy(prevBlock, 0, ciphertext, i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		}

		return ciphertext;
	}

	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/


	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

		int block_number = input.length / AES_BLOCK_SIZE;
		byte[] finalplaintext = new byte[block_number * AES_BLOCK_SIZE];

		d = new SymmetricEncryption(byteKey);

		byte[] prevBlock = new byte[AES_BLOCK_SIZE];
		byte[] currBlock = new byte[AES_BLOCK_SIZE];
		byte[] deciphered = new byte[AES_BLOCK_SIZE];

		System.arraycopy(iv, 0, prevBlock, 0, prevBlock.length);
		System.arraycopy(iv, 0, currBlock, 0, currBlock.length);

		// BLOQUES COMPLETOS (todos, en el caso de decrypt)
		for (int i = 0; i < block_number; i++) {
			for (int j = 0; j < AES_BLOCK_SIZE; j++)
				currBlock[j] = input[(i * AES_BLOCK_SIZE) + j];

			deciphered = s.decryptBlock(currBlock);

			//XOR
			for (int k = 0; k < AES_BLOCK_SIZE; k++)
				deciphered[k] ^= prevBlock[k];

			// Update prevBlock for the next block operation
			System.arraycopy(currBlock, 0, prevBlock, 0, AES_BLOCK_SIZE);

			System.arraycopy(deciphered, 0, finalplaintext, i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		}

		// Eliminate the padding (last block)
		// HE DEJADO ESTO POR SI NECESITAMOS VERIFICAR QUE EL PADDING ESTE BIEN,
		// QUE NO CREO QUE HAGA FALTA...
		/*
		byte pad = finalplaintext[(block_number * AES_BLOCK_SIZE) - 1];
		System.out.println("PADDING detected: " + pad);

		int expected = pad;

		for (int i = 0; i < AES_BLOCK_SIZE; i++) {
				if (expected <= 0)
					break;

				if(pad != finalplaintext[(block_number * AES_BLOCK_SIZE) - 1 - i]) {
					System.out.println("MAL: pad= "+pad+" final= "+finalplaintext[block_number * AES_BLOCK_SIZE -1 - i]);
					return null; //ERROR padding distinto
				}
				else
					expected--;
		}

		System.out.println("PADDING OK");

		finalplaintext = Arrays.copyOfRange(finalplaintext, 0, input.length - pad);
		*/

		finalplaintext = PKCS5Trimming(finalplaintext);

		return finalplaintext;
	}

	public static void main(String[] args) throws Exception {
		SymmetricCipher prueba = new SymmetricCipher();
		byte [] imp;

		byte[] padded;

		System.out.println("Encrypting...");
		imp = prueba.encryptCBC(iv2, iv);
		System.out.println("CIPHERTEXT");
		for(int i=0; i<imp.length;i++) {
			if(i % 16 == 0 && i != 0)
				System.out.println();
			if(i % 8 == 0)
				System.out.print(" ");

				System.out.printf("%02X ", imp[i]);
		}
		System.out.println();
		System.out.println();

		System.out.println("Decrypting...");
		imp = prueba.decryptCBC(imp, iv);

		System.out.println("PLAINTEXT");
		for (int i = 0; i < imp.length; i++) {
			if(i % 16 == 0 && i != 0)
				System.out.println();
			if(i % 8 == 0)
				System.out.print(" ");

			System.out.printf("%02X ", imp[i]);
		}

		for (int i = 0; i < iv2.length; i++) {
			if (iv2[i] != imp[i])
				System.out.println("TEST FAILED!!!!!!!!!!");
		}

		System.out.println();

	}

}
