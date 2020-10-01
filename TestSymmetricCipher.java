public class TestSymmetricCipher {
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
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54
    };

    private static byte[] testVectorShort = new byte[] {
        (byte)49, (byte)50, (byte)51, (byte)52
    };

    private static byte[] testVectorLong = new byte[] {
        (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
            (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, (byte)55, (byte)56,
            (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54,
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
            (byte)49, (byte)50, (byte)51, (byte)52
    };

    private boolean TestSymmetricCipherBasic(byte[] testVector) throws Exception {
        SymmetricCipher ciph = new SymmetricCipher();
        byte[] imp;

        imp = ciph.encryptCBC(testVector, SymmetricCipher.iv);
        imp = ciph.decryptCBC(imp, SymmetricCipher.iv);

        for (int i = 0; i < testVector.length; i++)
            if (testVector[i] != imp[i])
                return false;

        return true;
    }

    public static void main(String[] args) throws Exception {

        TestSymmetricCipher testSuite = new TestSymmetricCipher();

        System.out.print("Basic test: ");
        if (!testSuite.TestSymmetricCipherBasic(testVectorBasic))
            TEST_FAIL();
        else
            TEST_OK();

        System.out.print("Short input test: ");
        if (!testSuite.TestSymmetricCipherBasic(testVectorShort))
            TEST_FAIL();
        else
            TEST_OK();

        System.out.print("Long input test: ");
        if (!testSuite.TestSymmetricCipherBasic(testVectorLong))
            TEST_FAIL();
        else
            TEST_OK();

        System.out.print("ASCII input test: ");
        if (!testSuite.TestSymmetricCipherBasic(testVectorASCII))
            TEST_FAIL();
        else
            TEST_OK();
    }

}
