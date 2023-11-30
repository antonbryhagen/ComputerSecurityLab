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

        String messageString;

        RSAPrivateKey labOneKey = loadKey("../lab1Store", storePassword.toCharArray(), labOneKeyAlias, labOneKeyPassword.toCharArray());

        int textOffset = 384; // 3*128, start from this byt

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
            SecretKeySpec secretKey = new SecretKeySpec(key1, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher aesDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            byte[] message = aesDec.doFinal(encryptedMessage);
            messageString = new String(message, "UTF-8");
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
            SecretKeySpec secretKey2 = new SecretKeySpec(key2, "HmacMD5");
            mac.init(secretKey2);
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