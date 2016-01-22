import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.examples.ByteArrayHandler;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * Created by erlend on 22.01.16.
 */
public class GpgTest {

    public static void main(String[] args) {
        new GpgTest();
    }

    private static final String PASS = "S3cr3tP4ssw0rd";

    public GpgTest() {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            File unencryptedFile = new File(this.getClass().getResource("top_secret").getFile());
            File encryptedFile = new File(this.getClass().getResource("top_secret.gpg").getFile());

            byte[]  unencryptedByteArray = Files.readAllBytes(unencryptedFile.toPath());
            byte[]  encryptedByteArray = Files.readAllBytes(encryptedFile.toPath());

            byte[] decryptedByteArray = ByteArrayHandler.decrypt(encryptedByteArray, PASS.toCharArray());
            String decryptedString = new String(decryptedByteArray);

            System.out.println("Original string:  [" + new String(unencryptedByteArray) + "]");
            System.out.println("Decrypted string: [" + decryptedString + "]");

        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

    }
}
