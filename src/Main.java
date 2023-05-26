import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.util.Arrays.copyOfRange;

public class Main {

    public static byte[] stringToByteArray(String s, int bytes) {
        BigInteger big = new BigInteger(s, 16);
        byte[] byteArray =  big.toByteArray();
        if (byteArray.length != bytes) {
            int fillAmount = bytes-byteArray.length;
            byte[] rv = new byte[bytes];
            for (int i = 0; i < bytes; i++) {
                if (i < fillAmount) rv[i] = 0;
                else rv[i] = byteArray[i-fillAmount];
            }
            return rv;
        } else return byteArray;
    }

    public static void printByteArray(byte[] b) {
        int ptr = 0;

        while (ptr < b.length) {
            System.out.printf("%02x ", b[ptr]);
            if (ptr % 16 == 15) System.out.printf("\n");
            ptr += 1;
        }
    }

    public static void TestCase1() {
        Cipher cipher = null;
        byte[] expected = stringToByteArray("58e2fccefa7e3061367f1d57a4e7455a", 16);

        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, stringToByteArray("0", 12));
            SecretKeySpec secretKey = new SecretKeySpec(stringToByteArray("0", 16), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] cipherText = cipher.doFinal();

            if (Arrays.equals(cipherText, expected)) {
                System.out.println("Vectors compared OK");
            } else {
                System.out.println("Vectors compared failed");
                System.out.print("Expected:");
                printByteArray(expected);
                System.out.print("Received:");
                printByteArray(cipherText);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }

    public static void TestCase2() {
        Cipher cipher = null;
        byte[] expected = stringToByteArray("ab6e47d42cec13bdf53a67b21257bddf", 16);

        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, stringToByteArray("0", 12));
            SecretKeySpec secretKey = new SecretKeySpec(stringToByteArray("0", 16), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] aad = stringToByteArray("0", 16);
            cipher.update(aad);
            byte[] cipherText = cipher.doFinal();

            if (Arrays.equals(cipherText, expected)) {
                System.out.println("Vectors compared OK");
            } else {
                System.out.println("Vectors compared failed");
                System.out.print("Expected:");
                printByteArray(expected);
                System.out.print("Received:");
                printByteArray(cipherText);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }

    public static void TestCase4() {
        String key = "feffe9928665731c6d6a8f9467308308";
        String iv = "cafebabefacedbaddecaf888";
        String aad = "feedfacedeadbeeffeedfacedeadbeef" +
                "abaddad2";
        String ptext = "d9313225f88406e5a55909c5aff5269a" +
            "86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525" + "b16aedf5aa0de657ba637b39";
        String icv = "5bc94fbc3221a5db94fae95ae7121a47";

        GcmCryptoRequest req = new GcmCryptoRequest(key, iv, aad, ptext);
        byte[] result = req.getResult();
        byte[] receivedIcv = copyOfRange(result, result.length-16, result.length);
        byte[] expectedIcv = stringToByteArray(icv, 16);

        if (Arrays.equals(receivedIcv, expectedIcv)) {
            System.out.println("Vectors compared OK");
        } else {
            System.out.println("Vectors compared failed");
            System.out.print("Expected:");
            printByteArray(expectedIcv);
            System.out.print("Received:");
            printByteArray(receivedIcv);
        }
    }

    public static void main(String[] args) {
        TestCase1();
        TestCase2();
        TestCase4();
    }
}