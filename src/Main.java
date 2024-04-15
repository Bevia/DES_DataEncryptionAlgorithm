package symkey_block_ciphers;

/**
 * Data Encryption Standard
 *
 * block cipher
 * symmetric-key algorithm for encryption
 * block size: 64-bits
 * key length: 56-bits
 *
 * This example demonstrates the DES algorithm implementation without utilizing a file.
 */

/**
 * @author Vincent Bevia
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Main {
    private static final String ENCODING = "UTF-8";
    private static final String ALGORITHM = "DES";

    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, ENCODING))) {
            System.out.print("Enter text for encoding: ");
            String inputText = reader.readLine();

            SecretKey secretKey = generateSecretKey();
            byte[] encodedBytes = encodeText(inputText, secretKey);
            String encodedText = new String(encodedBytes, ENCODING);
            System.out.println("Coded text: " + encodedText);

            byte[] decodedBytes = decodeBytes(encodedBytes, secretKey);
            String decodedText = new String(decodedBytes, ENCODING);
            System.out.println("Decoding... " + decodedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        return keyGen.generateKey();
    }

    private static byte[] encodeText(String inputText, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] inputBytes = inputText.getBytes(ENCODING);
        return cipher.doFinal(inputBytes);
    }

    private static byte[] decodeBytes(byte[] encodedBytes, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encodedBytes);
    }
}


