import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.NameNotFoundException;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

public class Server {
    private static final String SERVER_CERT_FILE = "../CASignedServerCertificate.pem";
    private static final String SERVER_KEY_FILE = "../serverPrivateKey.der";
    private static ArrayList<byte[]> serverHAndShakeListMassege = new ArrayList<>();

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

    public static BigInteger genPubDHKeys(BigInteger PrivKey){
        return g.modPow(PrivKey, N);
    }

    public static void main(String[] args) throws Exception {
        int serverPort = 5678;


        System.out.println("sever start ");
        try (ServerSocket listener = new ServerSocket(serverPort)) {
            System.out.println("Listening at port " + serverPort);
//            while (true) {
                System.out.println("server in while true ");
                try(Socket socket = listener.accept();) {


                    System.out.println("server connected ");
                    ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
                    ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
                    System.out.println("sever in try after creating output and input true ");

                    // Receive client nonce
                    byte[] clientNonce = (byte[]) input.readObject();
                    //Add to the list of messages
                    serverHAndShakeListMassege.add(clientNonce);
                    System.out.println("Received client nonce: " + new String(clientNonce));

//------------------------------------------------------------------------------------------------//
                    // Create a SecureRandom instance
                    SecureRandom random = new SecureRandom();

                    // Load server certificate and private key
                    Certificate serverCert = TLSHelper.loadCertificate(SERVER_CERT_FILE);
                    PrivateKey privateKey = TLSHelper.loadPrivateKey(SERVER_KEY_FILE);

                  // Generate server's private key for Diffie-Hellman
                    BigInteger serverDHPriv = new BigInteger(2048, random);

                    //Server: sends the server certificate, serverDHPub, and a signed Diffie-Hellman public key as Enc(serverRSAPriv, serveDHPub)
                    // Load server certificate
                    Certificate serverCertificate = TLSHelper.loadCertificate(SERVER_CERT_FILE);

                   // Perform Diffie-Hellman key agreement
                    // Read  serverDHPublicKey
                    BigInteger serverDHPublicKey = g.modPow(serverDHPriv, N);

//                    // Send server certificate

                    output.writeObject(serverCertificate);
                    // Send server DH public key
                    output.writeObject(serverDHPublicKey);

                    // Sign DH public key and send
                    byte[] signedDHPub = TLSHelper.signData(serverDHPublicKey.toByteArray(), privateKey);
                    output.writeObject(signedDHPub);
                    output.flush();

                    //Add to the list of messages
                    serverHAndShakeListMassege.add(serverCertificate.getEncoded());
                    serverHAndShakeListMassege.add(serverDHPublicKey.toByteArray());
                    serverHAndShakeListMassege.add(signedDHPub);

////------------------------------------------------------------------------------------------------------------//
                    //Receive the certificate and public and signed DH from the client
                    //Read the certificate from the client
                    Certificate clientCert = (Certificate) input.readObject();
                    System.out.println("Client side received from server certificsate : " + clientCert.toString());
                    //Read the Public client DH from the server
                    BigInteger clientPublicKey = (BigInteger) input.readObject();
                    System.out.println("Client side received from client serverPublicKey : " + clientPublicKey.toString());
                    //Read the Public server DH  signed from the public
                    byte[] publicPublicSigned = (byte[]) input.readObject();
                    System.out.println("Client side received from server publicPublicSigned : " + publicPublicSigned.toString());

                    //Add to the list of messages --> received from the client
                    serverHAndShakeListMassege.add(clientCert.getEncoded());
                    serverHAndShakeListMassege.add(clientPublicKey.toByteArray());
                    serverHAndShakeListMassege.add(publicPublicSigned);


//--------------------------------------------------------------------------------------------------------------//
                    //The master secret key
                    BigInteger sharedSecretKey = clientPublicKey.modPow(serverDHPriv,N) ;
                    System.out.println("Server side sharedSecretKey : " + sharedSecretKey.toString());

                    //Make a secret key
                    TLSHelper.makeSecretKeys(clientNonce,sharedSecretKey.toByteArray());
//--------------------------------------------------------------------------------------------------------------//
                    //Server: send HMAC of all handshake messages so far using the server's MAC key to client.

                    // send MAC(serverMAC, historyMsg) to client
                    byte[] serverMAC = TLSHelper.mac(TLSHelper.serverMacKey,serverHAndShakeListMassege );
                    // Get public key from the certificate
                    PublicKey serverCertPublicKey = serverCert.getPublicKey();

                    // Send HMAC of all handshake messages so far using the server's MAC key to the client
                    output.writeObject(serverMAC);
                    output.flush();



////----------------------------------------------------------------------------------------------------------//
                    //Reading the testing message
                    byte[] messageReceivedFromClientEncoded = (byte[]) input.readObject();
                    //Decoded the message
                    byte[] messageReceivedFromClientDecoded = TLSHelper.decryptData(messageReceivedFromClientEncoded,TLSHelper.clientEncKey,TLSHelper.clientMacKey,TLSHelper.clientIV);
                    String result = TLSHelper.byteToString(messageReceivedFromClientDecoded);
                    System.out.println("Server side messageReceivedFromClientDecoded : " + result );
//-------------------------------------------------------------------------------------------------------------//
                    //Send to the client message received
                    byte[] messageToSendToClient = {70,60,30};
                    //
                    output.writeObject(TLSHelper.encryptData(messageToSendToClient,TLSHelper.serverEncKey,TLSHelper.serverMacKey,TLSHelper.serverIV));
                    output.flush();


//----------------------------------------------------------------------------------------------------------//
                    //Reading the testing message2
                    byte[] messageReceivedFromClientEncoded1 = (byte[]) input.readObject();
                    //Decoded the message
                    byte[] messageReceivedFromClientDecoded1 = TLSHelper.decryptData(messageReceivedFromClientEncoded1,TLSHelper.clientEncKey,TLSHelper.clientMacKey,TLSHelper.clientIV);
                    String result1 = TLSHelper.byteToString(messageReceivedFromClientDecoded1);
                    System.out.println("Server side messageReceivedFromClientDecoded : " + result1 );
//----------------------------------------------------------------------------------------------------------//

                    //Send to the client message received
                    //
                    output.writeObject(TLSHelper.encryptData(messageToSendToClient,TLSHelper.serverEncKey,TLSHelper.serverMacKey,TLSHelper.serverIV));
                    output.flush();



//----------------------------------------------------------------------------------------------------------//

                    // At this point, the handshake is complete
                    System.out.println("Handshake completed from  server successfully");

                }
                catch (IOException e) {
                    System.out.println("Handshake not completed from  server: " + e.getMessage());
                }
//            }
        }
        catch (IOException e) {
            System.out.println("Handshake not listening from  server: " + e.getMessage());
        }

    }


}
