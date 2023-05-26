import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class GcmCryptoRequest {
    final GCMParameterSpec parameterSpec;
    final SecretKeySpec secretKey;
    final byte[] aad;
    final byte[] plaintext;

    public GcmCryptoRequest(String key, String iv, String aad, String ptext) {
        secretKey = new SecretKeySpec(Main.stringToByteArray(key, 16), "AES");
        parameterSpec = new GCMParameterSpec(128, Main.stringToByteArray(iv, 12));
        this.aad = Main.stringToByteArray(aad, aad.length()/2);
        this.plaintext = Main.stringToByteArray(ptext, ptext.length()/2);
    }

    public byte[] getResult() {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            cipher.updateAAD(aad);
            cipher.update(plaintext);
            byte[] cipherText = cipher.doFinal();
            return cipherText;
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
}
