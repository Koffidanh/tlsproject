import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;


public class Client {
    private static final String SERVER_CERT_FILE = "../CASignedServerCertificate.pem";
    private static final String CLIENT_CERT_FILE = "../CASignedClientCertificate.pem";
    private static final String SERVER_PUBLIC_KEY_FILE = "../server_public.der";
    private static final String CLIENT_PRIVATE_KEY_FILE = "../clientPrivateKey.der";

    private static final String CLIENT_KEY_FILE = "../clientPrivateKey.der";

    private static ArrayList<byte[]> clientHAndShakeListMassege = new ArrayList<>();

    private static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger g = BigInteger.valueOf(2);

    public static BigInteger genPubDHKeys(BigInteger PrivKey) {
        return g.modPow(PrivKey, N);
    }

    public static void main(String[] args) throws Exception {
        int serverPort = 5678;

        try (Socket socket = new Socket("localhost", serverPort)) {

//            while (true) {
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

                // Create a SecureRandom instance
                SecureRandom random = new SecureRandom();

                // Generate a random nonce for the client
                byte[] nonce = new byte[32];
                random.nextBytes(nonce);

                // Send nonce to the server
                output.writeObject(nonce);
                output.flush();

                //Add to the list
                clientHAndShakeListMassege.add(nonce);

                System.out.println("Client sent the Nonce!");

//---------------------------------------------------------------------------------------------------//
            //Read the certificate from the server
            Certificate serverCert = (Certificate) input.readObject();
            System.out.println("Client side received from server certificsate : " + serverCert.toString());
            //Read the Public server DH from the server
            BigInteger serverPublicKey = (BigInteger) input.readObject();
            System.out.println("Client side received from server serverPublicKey : " + serverPublicKey.toString());
            //Read the Public server DH  signed from the server
            byte[] serverPublicSigned = (byte[]) input.readObject();
            System.out.println("Client side received from server serverPublicSigned : " + serverPublicSigned.toString());

            //Add to the list --> received from the server
            clientHAndShakeListMassege.add(serverCert.getEncoded());
            clientHAndShakeListMassege.add(serverPublicKey.toByteArray());
            clientHAndShakeListMassege.add(serverPublicSigned);

//----------------------------------------------------------------------------------------------------//
            //Sending the certificate, diffie hellman and signed key to the server

            // Load server certificate and private key
//            Certificate clientCert = loadCertificate(CLIENT_CERT_FILE);
            PrivateKey privateKey = TLSHelper.loadPrivateKey(CLIENT_KEY_FILE);

            // Generate client's private key for Diffie-Hellman
            BigInteger clientDHPriv = new BigInteger(2048, random);

            //Server: sends the client certificate, clientDHPub, and a signed Diffie-Hellman public key as Enc(serverRSAPriv, serveDHPub)
            // Load server certificate
            Certificate clientCertificate = TLSHelper.loadCertificate(SERVER_CERT_FILE);

            // Perform Diffie-Hellman key agreement
            //Read  serverDHPublicKey
            BigInteger clientDHPublicKey = g.modPow(clientDHPriv, N);

            // Send Client certificate

            output.writeObject(clientCertificate);
            // Send client DH public key
            output.writeObject(clientDHPublicKey);

            // Sign DH public key and send
            byte[] signedDHPub = TLSHelper.signData(clientDHPublicKey.toByteArray(), privateKey);
            output.writeObject(signedDHPub);
            output.flush();

            //Add to the list
            clientHAndShakeListMassege.add(clientCertificate.getEncoded());
            clientHAndShakeListMassege.add(clientDHPublicKey.toByteArray());
            clientHAndShakeListMassege.add(signedDHPub);
//----------------------------------------------------------------------------------------------------//
            //The master secret key
            BigInteger sharedSecretKey = serverPublicKey.modPow(clientDHPriv,N) ;
            System.out.println("Client side sharedSecretKey : " + sharedSecretKey.toString());

            //Make a secret key
            TLSHelper.makeSecretKeys(nonce,sharedSecretKey.toByteArray());
////-------------------------------------------------------------------------------------------------------//
            //Client: read HMAC of all handshake messages so far using the server's MAC key from server.
            // Receive HMAC of all handshake messages so far from the client
            byte[] serverHandshakeHMAC = (byte[]) input.readObject();

            // serverHandshakeHMAC = MAC(serverMAC, client_handshakeMsgs)
            byte[] macFromClient = TLSHelper.mac(TLSHelper.serverMacKey,clientHAndShakeListMassege);

            if(Arrays.equals(serverHandshakeHMAC,macFromClient)){
                System.out.println("Client side HMAC  and From the server side HMAC match! " );
            }
            else {
                System.out.println("Client side HMAC  and From the server side HMAC  dont match! ");
//                System.out.println("Client side serverHandshakeHMAC  and From the server side serverHandshakeHMAC ! " + serverHandshakeHMAC.toString() + " ------ " + (mac(TLSHelper.clientEncKey,clientHAndShakeListMassege)).toString() );
            }



////------------------------------------------------------------------------------------------------------//
            //Message
            byte[] clientPlanitext_1 = {10, 20, 30};
            byte[] client_cipherText1 = TLSHelper.encryptData(clientPlanitext_1, TLSHelper.clientEncKey,TLSHelper.clientMacKey, TLSHelper.clientIV);
            output.writeObject(client_cipherText1);
            output.flush();
            System.out.println("Message1 sent! " );
            // reading the server message
            byte[] exampleTest = {70,60,30};
            byte[] testReceiveFromServerEncoded = (byte[]) input.readObject();
            byte[] testReceiveFromServerDecoded = TLSHelper.decryptData(testReceiveFromServerEncoded,TLSHelper.serverEncKey,TLSHelper.serverEncKey,TLSHelper.serverIV);
            //Check message sent
            if(!Arrays.equals(testReceiveFromServerDecoded, exampleTest)){
                System.out.println("Message sent from SERVER and Decoded from client dont match!");
            }
            System.out.println("Message 1 check!");
            //Message 2
            byte[] clientPlanitext_2 = {50, 60, 70};
            byte[] client_cipherText2 = TLSHelper.encryptData(clientPlanitext_2, TLSHelper.clientEncKey,TLSHelper.clientMacKey, TLSHelper.clientIV);
            output.writeObject(client_cipherText2);
            output.flush();
            System.out.println("Message2 sent! " );

            // reading the server message
            byte[] testReceiveFromServerEncoded1 = (byte[]) input.readObject();
            byte[] testReceiveFromServerDecoded1 = TLSHelper.decryptData(testReceiveFromServerEncoded1,TLSHelper.serverEncKey,TLSHelper.serverMacKey,TLSHelper.serverIV);
            //Check message sent
            if(!Arrays.equals(testReceiveFromServerDecoded1, exampleTest)){
                System.out.println("Message sent from SERVER and Decoded from client dont match!");
            }
            System.out.println("Message 2 check!");


//-----------------------------------------------------------------------------------------------------------//

                // At this point, the handshake is complete
                System.out.println("Handshake completed from the client successfully");

        }
        catch (IOException e) {
            System.out.println("Handshake not listening from  Client: " + e.getMessage());
        }

    }

}
