import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.IIOException;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;

public class Main {

    private static final int RSA_KEY_MODULE_LENGTH = 2048;
    private static final String TEXT_FILE_PATH = "lab3Text.txt";
    private static final String RSA_ENCRYPTED_FILE_PATH = "lab1TextRSAEnc.txt";
    private static final String RSA_DECRYPTED_FILE_PATH = "lab1TextRSADec.txt";

    public static void main(String[] args) {
        try {
            KeyPairGenerator RSAKPGenerator = KeyPairGenerator.getInstance("RSA");
            RSAKPGenerator.initialize(RSA_KEY_MODULE_LENGTH); // length of RSA key module(N)

            KeyPair RSAKeyPair = RSAKPGenerator.generateKeyPair();
            PrivateKey RSAPrivateKey = RSAKeyPair.getPrivate();
            PublicKey RSAPublicKey = RSAKeyPair.getPublic();

            byte[] textBytes = readFile(TEXT_FILE_PATH);

            System.out.println("Text: " + new String(textBytes));
            System.out.println("Text in bytes: " + Arrays.toString(textBytes));

            Cipher RSACipher = Cipher.getInstance("RSA");
            RSACipher.init(Cipher.ENCRYPT_MODE, RSAPublicKey);

            byte[] encTextBytes = RSACipher.doFinal(textBytes);

            writeToFile(RSA_ENCRYPTED_FILE_PATH, encTextBytes);
            System.out.println("RSA encrypted text in bytes: "+ Arrays.toString(encTextBytes));
            System.out.println("RSA encrypted text: " + new String(encTextBytes));

            RSACipher.init(Cipher.DECRYPT_MODE, RSAPrivateKey);

            textBytes = RSACipher.doFinal(encTextBytes);
            writeToFile(RSA_DECRYPTED_FILE_PATH, textBytes);
            System.out.println("RSA decrypted text in bytes: " + Arrays.toString(textBytes));
            System.out.println("RSA decrypted text: " + new String(textBytes));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

    }

    public static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    public static void writeToFile(String path, byte[] bytes) throws IIOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(bytes);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    public void findPrivateExp(final int T, final int e) {
        int ed;
        int n = 1;
        while (((ed = (T * n + 1)) % e) != 0) {
            n++;
        }
        System.out.println("d = " + ed / e);
    }

}
