import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) {

        byte[] encKey1 = readCiphertext(0, 128);
        byte[] encIV = readCiphertext(128, 128);
        byte[] encKey2 = readCiphertext(256, 128);
        byte[] encryptedMessage = readCiphertext(384, 1424);

        byte[] key1 = decryptKey(encKey1);
        byte[] key2 = decryptKey(encKey2);
        byte[] iv = decryptKey(encIV);

        String messageString;

        messageString = decryptMessage(key1, iv, encryptedMessage);
        System.out.println(messageString);
        verifyMac(messageString, key2);
        verifySignature(messageString);


    }

    public static byte[] readCiphertext(int offset, int byteSize){
        byte[] buffer = new byte[offset];
        byte[] byteArray = new byte[byteSize];
        File f = new File("../ciphertext.enc");
        try {
            FileInputStream fileInStream = new FileInputStream(f);
            fileInStream.read(buffer);
            fileInStream.read(byteArray);
            return byteArray;
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptKey(byte[] key){
        String storePassword = "lab1StorePass";
        String labOneKeyPassword = "lab1KeyPass";
        String labOneKeyAlias = "lab1EncKeys";
        byte[] decryptedKey = new byte[128];
        RSAPrivateKey labOneKey = loadKey("../lab1Store", storePassword.toCharArray(), labOneKeyAlias, labOneKeyPassword.toCharArray());

        try {
            Cipher rsaDec = Cipher.getInstance("RSA");
            rsaDec.init(Cipher.DECRYPT_MODE, labOneKey);
            decryptedKey = rsaDec.doFinal(key);
            return decryptedKey;
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
    }

    public static String decryptMessage(byte[] key, byte[] iv, byte[] encryptedMessage){
        try{
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            byte[] message = aesDec.doFinal(encryptedMessage);
            String messageString = new String(message, "UTF-8");
            return messageString;
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

    public static void verifyMac(String messageString, byte[] key){
        String macOne = "";
        String macTwo = "";

        String calculatedMac = "";

        try {

            Scanner readMac = new Scanner(new File("../ciphertext.mac1.txt"));
            while(readMac.hasNext()){
                macOne = readMac.nextLine();
            }
            readMac = new Scanner(new File("../ciphertext.mac2.txt"));
            while(readMac.hasNext()){
                macTwo = readMac.nextLine();
            }
            readMac.close();

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        byte[] macVal = null;
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacMD5");
            mac.init(secretKey);
            mac.update(messageString.getBytes());
            macVal = mac.doFinal();
            calculatedMac = bytesToHex(macVal);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        System.out.println("-----------------------------------");
        if (calculatedMac.equals(macOne)){
            System.out.println("Mac One is correct; found in ciphertext.mac1.txt");
        } else if (calculatedMac.equals(macTwo)) {
            System.out.println("Mac Two is correct; found in ciphertext.mac2.txt");
        }else{
            System.out.println("Calculated mac doesn't match any provided mac");
        }
    }

    public static void verifySignature(String messageString){
        byte[] sigOne = new byte[128];
        byte[] sigTwo = new byte[128];

        boolean sigOneVerified = false;
        boolean sigTwoVerified = false;

        try {
            FileInputStream fileInStream = new FileInputStream("../ciphertext.enc.sig1");
            fileInStream.read(sigOne);
            fileInStream = new FileInputStream("../ciphertext.enc.sig2");
            fileInStream.read(sigTwo);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            FileInputStream readPuKey = new FileInputStream("../lab1Sign.cert");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate certificate = cf.generateCertificate(readPuKey);
            PublicKey puKey = certificate.getPublicKey();

            Signature myVerify = Signature.getInstance("SHA1withRSA");
            myVerify.initVerify(puKey);
            myVerify.update(messageString.getBytes());
            sigOneVerified = myVerify.verify(sigOne);

            myVerify.initVerify(puKey);
            myVerify.update(messageString.getBytes());
            sigTwoVerified = myVerify.verify(sigTwo);

            System.out.println("-----------------------------------");
            if (sigOneVerified){
                System.out.println("Signature One is correct; found in ciphertext.enc.sig1");
            } else if (sigTwoVerified) {
                System.out.println("Signature Two is correct; found in ciphertext.enc.sig2");
            }else{
                System.out.println("No valid signature found");
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}