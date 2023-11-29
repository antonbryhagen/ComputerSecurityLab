import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;

public class Main {
    public static void main(String[] args) {
        byte[] encKey1 = new byte[128];
        byte[] encKey2 = new byte[128];
        byte[] encIV = new byte[128];

        byte[] key1 = new byte[128];
        byte[] key2 = new byte[128];
        byte[] iv = new byte[128];

        byte[] encryptedMessage = new byte[1424];

        String storePassword = "lab1StorePass";
        String labOneKeyPassword = "lab1KeyPass";
        String labOneKeyAlias = "lab1EncKeys";

        RSAPrivateKey labOneKey = loadKey("../lab1Store", storePassword.toCharArray(), labOneKeyAlias, labOneKeyPassword.toCharArray());

        int textOffset = 384; // 3*128, start from this byte

        File f = new File("../ciphertext.enc");
        try {
            FileInputStream fileInStream = new FileInputStream(f);
            fileInStream.read(encKey1);
            fileInStream.read(encIV);
            fileInStream.read(encKey2);
            fileInStream.read(encryptedMessage);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            Cipher rsaDec = Cipher.getInstance("RSA");
            rsaDec.init(Cipher.DECRYPT_MODE, labOneKey);
            key1 = rsaDec.doFinal(encKey1);
            key2 = rsaDec.doFinal(encKey2);
            iv = rsaDec.doFinal(encIV);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        try{
            SecretKey secretKey = new SecretKeySpec(key1, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            byte[] message = aesDec.doFinal(encryptedMessage);
            String messageString = new String(message, "UTF-8");
            System.out.println(messageString);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static RSAPrivateKey loadKey(String storeFileName, char[] storePassword, String alias, char[] keyPassword){

            try {
                //load keystore
                KeyStore myStore = KeyStore.getInstance("JCEKS");
                FileInputStream loadFile = new FileInputStream(storeFileName);
                myStore.load(loadFile, storePassword); //filename and pw that protect keystore
                loadFile.close();
                //load key
                RSAPrivateKey theKey = (RSAPrivateKey) myStore.getKey(alias, keyPassword);
                return theKey;
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (UnrecoverableKeyException e) {
                throw new RuntimeException(e);
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

    }
}