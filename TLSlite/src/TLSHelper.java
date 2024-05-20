import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class TLSHelper {
    public static SecretKey serverEncKey;
    public static SecretKey clientEncKey;
    public static SecretKey serverMacKey;
    public static SecretKey clientMacKey;
    public static IvParameterSpec serverIV;
    public static IvParameterSpec clientIV;

    public static byte[] hkdfExpand(byte[] inputKeyMaterial, String tag) throws Exception {

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(inputKeyMaterial, "HmacSHA256"));
        hmac.update(tag.getBytes());
        hmac.update((byte) 1);
        byte[] okm = hmac.doFinal();
        byte[] result = new byte[16];
        System.arraycopy(okm, 0, result, 0, 16);
        return result;
    }


    public static void makeSecretKeys(byte[] clientNonce, byte[] sharedSecretFromDiffieHellman) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(clientNonce, "HmacSHA256"));

        byte[] prk = hmac.doFinal(sharedSecretFromDiffieHellman);
        byte[] serverEncrypt = hkdfExpand(prk, "server encrypt");
        byte[] clientEncrypt = hkdfExpand(serverEncrypt, "client encrypt");
        byte[] serverMAC = hkdfExpand(clientEncrypt, "server MAC");
        byte[] clientMAC = hkdfExpand(serverMAC, "client MAC");
        byte[] serverIVbytes = hkdfExpand(clientMAC, "server IV");
        byte[] clientIVbytes = hkdfExpand(serverIVbytes, "client IV");

        serverEncKey = new SecretKeySpec(serverEncrypt, "HmacSHA256");
        clientEncKey = new SecretKeySpec(clientEncrypt, "HmacSHA256");
        serverMacKey = new SecretKeySpec(serverMAC, "HmacSHA256");
        clientMacKey = new SecretKeySpec(clientMAC, "HmacSHA256");

        serverIV = new IvParameterSpec(serverIVbytes);
        clientIV = new IvParameterSpec(clientIVbytes);



    }


    //Encrypt data using RSA-OAEP
    public static byte[] encryptData(byte[] data, SecretKey encryServerKey, SecretKey serverMAC, IvParameterSpec serverIVbytes) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(serverMAC);
        byte[] HMAC =  hmac.doFinal(data);

        // Concatenate data and HMAC
        byte[] encryptedDataWithHMAC = new byte[data.length + HMAC.length];
        System.arraycopy(data, 0, encryptedDataWithHMAC, 0, data.length);
        System.arraycopy(HMAC, 0, encryptedDataWithHMAC, data.length, HMAC.length);


        // Encrypt the concatenated data
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(encryServerKey.getEncoded(),"AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, serverIVbytes);

        return cipher.doFinal(encryptedDataWithHMAC);
    }

    // Decrypt data using RSA-OAEP
    public static byte[] decryptData(byte[] data, SecretKey encryClientKey, SecretKey serverMAC, IvParameterSpec serverIVbytes) throws Exception {// Decrypt the data
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(encryClientKey.getEncoded(),"AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, serverIVbytes);


        byte[] decryptedDataWithHMAC = cipher.doFinal(data);

//        Mac hmac = Mac.getInstance("HmacSHA256");


        // Extract HMAC from decrypted data
        int dataLength = decryptedDataWithHMAC.length - 32;
        byte[] dataBytes = new byte[dataLength];
        byte[] receivedHMAC = new byte[serverMAC.getEncoded().length];
        System.arraycopy(decryptedDataWithHMAC, 0, dataBytes, 0, dataLength);
        System.arraycopy(decryptedDataWithHMAC, dataLength, receivedHMAC, 0, serverMAC.getEncoded().length);



        //Compute the HMAC of the message
        Mac computeHMAC = Mac.getInstance("HmacSHA256");
        computeHMAC.init(encryClientKey);


        return dataBytes;
    }
    public static String byteToString(byte[] val){
//        return new String(val, StandardCharsets.UTF_8);
        String s = Arrays.toString(val);
//        return new String(val, "")
                return s;
    }

    public static PrivateKey loadPrivateKey(String keyFile) throws Exception {
        FileInputStream keyFileInputStream = new FileInputStream(keyFile);
        byte[] privateKeyBytes = new byte[keyFileInputStream.available()];
        keyFileInputStream.read(privateKeyBytes);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }


    public static Certificate loadCertificate(String certFile) throws Exception {
        FileInputStream certFileInputStream = new FileInputStream(certFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate cert = certificateFactory.generateCertificate(certFileInputStream);
        certFileInputStream.close();
        return cert;
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static byte[] mac(SecretKey data, ArrayList<byte[]> lists) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(data);
        for(byte[] c : lists){
            mac.update(c);
        }
        return mac.doFinal();
    }

}
