/**
 * @Author: Guillermo Escobero, Alvaro Santos
 * @Date:   04-10-2020
 * @Project: Data Protection Lab 2
 * @Filename: TestRSALibrary.java
 * @Last modified by:   Guillermo Escobero, Alvaro Santos
 * @Last modified time: 04-10-2020
 */



package test.java.lab2;

import main.java.lab2.RSALibrary;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;
import java.util.Arrays;

public class TestRSALibrary {

    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";

    private static void TEST_OK() {
        System.out.println(ANSI_GREEN + "PASS" + ANSI_RESET);
    }

    private static void TEST_FAIL() {
        System.out.println(ANSI_RED + "FAIL" + ANSI_RESET);
    }

    private static byte[] testVectorBasic = new byte[] {
        (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54
    };

    private static byte[] testVectorASCII = new byte[] {
        (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)128, (byte)138, (byte)167, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126,
            (byte)24, (byte)33, (byte)38, (byte)56, (byte)128, (byte)138, (byte)167,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126,
            (byte)128, (byte)138, (byte)167, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)128, (byte)138, (byte)167, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126,
            (byte)24, (byte)33, (byte)38, (byte)56, (byte)128, (byte)138, (byte)167,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126,
            (byte)128, (byte)138, (byte)167, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)128, (byte)138, (byte)167, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126,
            (byte)24, (byte)33, (byte)38, (byte)56, (byte)128, (byte)138, (byte)167,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)64, (byte)66, (byte)94, (byte)126,
            (byte)128, (byte)138, (byte)167, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)64, (byte)66, (byte)94, (byte)126, (byte)24, (byte)33, (byte)38, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52
    };

    private boolean TestRSALibraryEncryption(byte[] test, PublicKey publicK, PrivateKey privateK) throws Exception {

        RSALibrary rsa = new RSALibrary();
        byte[] cipherText = rsa.encrypt(test, publicK);
        byte[] decrypted  = rsa.decrypt(cipherText, privateK);

        if (cipherText == null || decrypted == null)
            return false;

        return Arrays.equals(test, decrypted);
    }

    private boolean TestRSALibrarySignature(byte[] test, PublicKey publicKey, PrivateKey privateKey) throws Exception {

        RSALibrary rsa = new RSALibrary();
        byte[] signed = rsa.sign(test, privateKey);

        return rsa.verify(test, signed, publicKey);
    }

    public static void main(String[] args) throws Exception {

        TestRSALibrary testSuite = new TestRSALibrary();

        RSALibrary rsa = new RSALibrary();
        rsa.generateKeys();

        PrivateKey privateKey = (PrivateKey)rsa.fileToKey(RSALibrary.PRIVATE_KEY_FILE);
        PublicKey publicKey = (PublicKey)rsa.fileToKey(RSALibrary.PUBLIC_KEY_FILE);

        System.out.print("Short encryption test: ");
        if (!testSuite.TestRSALibraryEncryption(testVectorBasic, publicKey, privateKey))
            TEST_FAIL();
        else
            TEST_OK();

        System.out.print("Extended encryption test: ");
        if (!testSuite.TestRSALibraryEncryption(testVectorASCII, publicKey, privateKey))
            TEST_FAIL();
        else
            TEST_OK();

        System.out.print("Short signature test: ");
        if (!testSuite.TestRSALibrarySignature(testVectorBasic, publicKey, privateKey))
            TEST_FAIL();
        else
            TEST_OK();

        System.out.print("Extended signature test: ");
        if (!testSuite.TestRSALibrarySignature(testVectorASCII, publicKey, privateKey))
            TEST_FAIL();
        else
            TEST_OK();

    }
}
