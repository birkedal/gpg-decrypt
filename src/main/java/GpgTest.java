import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.examples.ByteArrayHandler;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.apache.commons.io.IOUtils;

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

            byte[]  encryptedByteArray = Files.readAllBytes(encryptedFile.toPath());

            byte[] decryptedByteArray = ByteArrayHandler.decrypt(encryptedByteArray, PASS.toCharArray());
            String decryptedString = new String(decryptedByteArray);

            System.out.printf("Original content:\n[%s]\n\n", read(new FileInputStream(unencryptedFile)));
            System.out.printf("Decrypted byte array:\n[%s]\n\n", decryptedString);
            System.out.printf("Decrypted stream:\n[%s]\n\n", read(decrypt(new FileInputStream(encryptedFile), PASS)));

        } catch (IOException | PGPException | NoSuchProviderException e) {
            e.printStackTrace();
        }

    }

    // Adjusted org.bouncycastle.openpgp.examples.ByteArrayHandler.decrypt() to take and return streams
    private InputStream decrypt(InputStream inputStream, String passphrase) throws IOException, PGPException {
        InputStream decoderStream = PGPUtil.getDecoderStream(inputStream);
        JcaPGPObjectFactory jcaPGPObjectFactory = new JcaPGPObjectFactory(decoderStream);
        Object nextObject = jcaPGPObjectFactory.nextObject();
        PGPEncryptedDataList pgpEncryptedDataList;
        if(nextObject instanceof PGPEncryptedDataList) {
            pgpEncryptedDataList = (PGPEncryptedDataList) nextObject;
        } else {
            pgpEncryptedDataList = (PGPEncryptedDataList)jcaPGPObjectFactory.nextObject();
        }

        PGPPBEEncryptedData pgppbeEncryptedData = (PGPPBEEncryptedData)pgpEncryptedDataList.get(0);
        InputStream dataStream = pgppbeEncryptedData.getDataStream((new JcePBEDataDecryptorFactoryBuilder((new JcaPGPDigestCalculatorProviderBuilder()).setProvider("BC").build())).setProvider("BC").build(passphrase.toCharArray()));
        JcaPGPObjectFactory jcaPGPObjectFactoryOfDataStream = new JcaPGPObjectFactory(dataStream);
        PGPCompressedData pgpCompressedData = (PGPCompressedData)jcaPGPObjectFactoryOfDataStream.nextObject();
        jcaPGPObjectFactoryOfDataStream = new JcaPGPObjectFactory(pgpCompressedData.getDataStream());
        PGPLiteralData pgpLiteralData = (PGPLiteralData)jcaPGPObjectFactoryOfDataStream.nextObject();
        return pgpLiteralData.getInputStream();
    }

    public String read(InputStream input) throws IOException {
        return IOUtils.toString(input);
    }
}
