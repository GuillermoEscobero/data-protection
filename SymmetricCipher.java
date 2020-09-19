import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import java.security.InvalidKeyException;

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
		(byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
			(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
			(byte)53, (byte)54,
			(byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
				(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
				(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public void SymmetricCipher() {
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {

		int block_number = input.length / AES_BLOCK_SIZE;
		byte[] ciphertext = new byte[(block_number + 1) * AES_BLOCK_SIZE];

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

		// PADDING section
		pad = (byte)(AES_BLOCK_SIZE - (input.length % AES_BLOCK_SIZE));

		if (pad == 0) {
			// Bloque extra de padding
			pad = (byte)AES_BLOCK_SIZE;
		}

		for (int i = (AES_BLOCK_SIZE - pad); i < AES_BLOCK_SIZE; i++) {
			currBlock[i] = pad;
		}

		// XOR of the block with padding
		for (int k = 0; k < AES_BLOCK_SIZE; k++) {
			currBlock[k] ^= prevBlock[k];
		}

		prevBlock = s.encryptBlock(currBlock);

		System.arraycopy(prevBlock, 0, ciphertext, block_number*AES_BLOCK_SIZE, AES_BLOCK_SIZE);

		return ciphertext;
	}

	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/


	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {

		int block_number = input.length / AES_BLOCK_SIZE;
		byte[] finalplaintext = new byte[block_number * AES_BLOCK_SIZE];

		d = new SymmetricEncryption(byteKey);

		byte pad;

		byte[] prevBlock = new byte[AES_BLOCK_SIZE];
		byte[] currBlock = new byte[AES_BLOCK_SIZE];
		byte[] deciphered = new byte[AES_BLOCK_SIZE];

		System.arraycopy(iv, 0, prevBlock, 0, prevBlock.length);
		System.arraycopy(iv, 0, currBlock, 0, currBlock.length);

		// BLOQUES COMPLETOS
		for (int i = 0; i < block_number; i++) {
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				currBlock[j] = input[(i * AES_BLOCK_SIZE) + j];
			}

			deciphered = s.decryptBlock(currBlock);

			//XOR
			for (int k = 0; k < AES_BLOCK_SIZE; k++) {
				deciphered[k] ^= prevBlock[k];
			}

			for (int k = 0; k < AES_BLOCK_SIZE; k++) {
				prevBlock[k] = currBlock[k];
			}

			System.arraycopy(deciphered, 0, finalplaintext, i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		}

		// Eliminate the padding



		return finalplaintext;
	}

	public static void main(String[] args) throws Exception {
		SymmetricCipher prueba = new SymmetricCipher();
		byte [] imp;

		imp = prueba.encryptCBC(iv2, iv);
		for(int i=0; i<imp.length;i++) {
			if(i % 16 == 0)
				System.out.println();
			if(i % 8 == 0)
				System.out.print(" ");

			System.out.printf("%02X ", imp[i]);
		}
		System.out.println();

		imp = prueba.decryptCBC(imp, iv);
		for (int i = 0; i < imp.length; i++) {
			if(i % 16 == 0)
				System.out.println();
			if(i % 8 == 0)
				System.out.print(" ");

			System.out.printf("%02X ", imp[i]);
		}

		System.out.println();

	}

}
