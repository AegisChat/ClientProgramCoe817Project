import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ClientConnect implements  Runnable{
    private static final String RSA = "RSA";
    private static final String DES = "DES";

    private Socket socket;
    private InputStream inputStream;
    private OutputStream outputStream;

    private BufferedReader bufferedReader;
    private PrintWriter printWriter;

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    private KeyPair keyPair;
    private KeyPairGenerator keyPairGenerator;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    private X509EncodedKeySpec x509EncodedKeySpec;
    private PublicKey clientPublicKey;
    private SecretKey secretKey;
    private Key key;

    public ClientConnect(Socket socket){
        this.socket = socket;

        try {
            bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            printWriter = new PrintWriter(socket.getOutputStream(), true);
            encryptCipher = Cipher.getInstance(RSA);
            decryptCipher = Cipher.getInstance(RSA);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    private void init(){
        try{
            System.out.println("Key distribution initialization is starting now:");
            //************************************************
            //GENERATE THE PUBLIC/PRIVATE KEYS
            //************************************************
            keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(1024);
            keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();

            System.out.println("************************************************");
            System.out.println("PUBLIC KEY: " + publicKey);
            System.out.println("************************************************");
            System.out.println("");
            System.out.println("************************************************");
            System.out.println("PRIVATE KEY: " + privateKey);
            System.out.println("************************************************");
            System.out.println("");

            //************************************************
            //SEND THE PUBLIC KEY
            //************************************************

            printWriter.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            //************************************************
            //GET PUBLIC KEY OF CLIENT
            //************************************************

            String input = bufferedReader.readLine();

            x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(input));
            clientPublicKey = KeyFactory.getInstance(RSA).generatePublic(x509EncodedKeySpec);

            System.out.println("************************************************");
            System.out.println("Client Public Key: " + clientPublicKey);
            System.out.println("************************************************");
            System.out.println("");

            //************************************************
            //SET UP CIPHER
            //************************************************

            encryptCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

            String encryptedKey = bufferedReader.readLine();

            System.out.println("************************************************");
            System.out.println("ENCRYPTED DES KEY: " + encryptedKey);
            System.out.println("************************************************");
            System.out.println("");
            decryptCipher.init(Cipher.UNWRAP_MODE, privateKey);
            byte[] keyByte = Base64.getDecoder().decode(encryptedKey);
            key = decryptCipher.unwrap(keyByte, DES, Cipher.SECRET_KEY);

            System.out.println("************************************************");
            System.out.println("RECIEVED DES KEY: " + key.toString());
            System.out.println("************************************************");
            System.out.println("");

            encryptCipher = Cipher.getInstance(DES);
            decryptCipher = Cipher.getInstance(DES);
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);
            decryptCipher.init(Cipher.DECRYPT_MODE, key);


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        System.out.println("Key distribution initialization has ended.");
    }

    public void readFromServer(){
        try {
            String encryptedMessage;
            while((encryptedMessage = bufferedReader.readLine())!=null) {
                byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage.getBytes());
                byte[] messageBytes = decryptCipher.doFinal(encryptedBytes);
                String message = new String(messageBytes);
                System.out.println(message);
            }

        }catch (IOException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }//thats cleaner
    }

    public void writeToServer(String message){
        byte[] messageBytes = message.getBytes();
        try{
            byte[] encryptedMessage = encryptCipher.doFinal(messageBytes);
            encryptedMessage = Base64.getEncoder().encode(encryptedMessage);
            String encryptedString = new String(encryptedMessage);
            printWriter.println(encryptedString);
        }catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
}

    @Override
    public void run() {
        init();
        readFromServer();
    }
}
