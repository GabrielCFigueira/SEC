package sec.dpas;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.ConnectException;

import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.sound.sampled.SourceDataLine;

import sec.dpas.exceptions.SigningException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Client
 *
 */
public class Client {

    private PrivateKey _privKey;
    private PublicKey _pubkey;
    private final String _keystorePassword = "keystore";
    private int annId = 0;

    public Client() throws FileNotFoundException, IOException {
        try {
            _privKey = Crypto.readPrivateKey("../resources/key.store", "test", _keystorePassword, "testtest");
        } catch(KeyStoreException e) {
            System.out.println("KeyStoreException");
        } catch(UnrecoverableKeyException e) {
            System.out.println("UnrecoverableKeyException");
        } catch(NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");
        } catch(CertificateException e) {
            System.out.println("CertificateException");
        }

        _pubkey = Crypto.readPublicKey("../resources/test.pub");
    }

    public Client(String keyName) throws FileNotFoundException, IOException {
        try {
            _privKey = Crypto.readPrivateKey("../resources/key.store", keyName, _keystorePassword, "test" + keyName);
        } catch(KeyStoreException e) {
            System.out.println("KeyStoreException");
        } catch(UnrecoverableKeyException e) {
            System.out.println("UnrecoverableKeyException");
        } catch(NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");
        } catch(CertificateException e) {
            System.out.println("CertificateException");
        }

        _pubkey = Crypto.readPublicKey("../resources/" + keyName + ".pub");
    }

    protected PrivateKey getPrivateKey() throws FileNotFoundException, IOException{ return _privKey; }

    public PublicKey getPublicKey() throws FileNotFoundException, IOException{ return _pubkey; }

    public Message reCreateMessage() {
        return null;
    }

    /**
     * printOptions
     *
     */
    public void printOptions() {
        System.out.println("#=========================================#");
        System.out.println("| Options:                                |");
        System.out.println("| 1 - Register User (must register first) |");
        System.out.println("| 2 - Post an Announcement                |");
        System.out.println("| 3 - Post an Announcement to General     |");
        System.out.println("| 4 - Read Announcements                  |");
        System.out.println("| 5 - Read General Announcements          |");
        System.out.println("| 6 - Exit Application                    |");
        System.out.println("#=========================================#");
    }

    /**
     * printAnnouncements
     *
     */
    public void printAnnouncements(ArrayList<Announcement> anns) {
        System.out.println("Announcements:");
        for (Announcement ann: anns){
          System.out.println("----------------------------");
          System.out.println("Announcement: " + ann.getId());
          System.out.println("Message: " + ann.getMessage());
          System.out.println("References: " + ann.getReferences());
          System.out.println("----------------------------");
        }
    }

    /**
     * registerOption
     *
     */
    public String registerOption(ServerAPI stub) throws IOException, FileNotFoundException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();
        Message message = new Message();
	long clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        // call function from ServerAPI
        Response response = stub.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));


        // verificacao da assinatura da response
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
        Message messageReceived = new Message();

        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());

        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
       		return "Signature verification failed";
	else if(clientNonce != response.getClientNonce())
		return "Server returned invalid nonce: possible replay attack";
	else
	        return response.getStatusCode();
    }

    /**
     * postOption
     *
     */
    public String postOption(ServerAPI stub) throws IOException, FileNotFoundException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

	//requesting nonce
	Message message = new Message();
	message.appendObject(pubkey);
	long clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	//response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
	Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else if(response.getStatusCode() != "Nonce generated")
		return response.getStatusCode();
        long serverNonce = response.getServerNonce();
	
	// creating Announcement
        Announcement a = this.createAnnouncement();

        // creating Message
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);

        // call post from ServerAPI
        response = stub.post(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());

	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else
		return response.getStatusCode();
    }

    /**
     * postGeneralOption
     *
     */
    public String postGeneralOption(ServerAPI stub) throws IOException, FileNotFoundException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

	//requesting nonce
	Message message = new Message();
	message.appendObject(pubkey);
	long clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	//response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
	Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else if(response.getStatusCode() != "Nonce generated")
		return response.getStatusCode();
        long serverNonce = response.getServerNonce();
        
	// creating Announcement
        Announcement a = this.createAnnouncement();

        // creating Message
        message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);

        // call post from ServerAPI
        response = stub.postGeneral(pubkey, a, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());

	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else
		return response.getStatusCode();
    }

    /**
     * readOption
     *
     */
    public String readOption(ServerAPI stub, int number, PublicKey pubkeyToRead) throws IOException, FileNotFoundException, SigningException, ClassNotFoundException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

	//requesting nonce
	Message message = new Message();
	message.appendObject(pubkey);
	long clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	//response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
	Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else if(response.getStatusCode() != "Nonce generated")
		return response.getStatusCode();
        long serverNonce = response.getServerNonce();
        
	message = new Message();
        message.appendObject(pubkey);
        message.appendObject(number);
        message.appendObject(pubkeyToRead);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);
        response = stub.read(pubkeyToRead, number, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getAnnouncements());

	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else {
            	this.printAnnouncements(response.getAnnouncements());
		return response.getStatusCode();
        }
    }

    /**
     * readGeneralOption
     *
     */
    public String readGeneralOption(ServerAPI stub, int number) throws IOException, FileNotFoundException, SigningException, ClassNotFoundException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

	//requesting nonce
	Message message = new Message();
	message.appendObject(pubkey);
	long clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
	//response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
	Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else if(response.getStatusCode() != "Nonce generated")
		return response.getStatusCode();
        long serverNonce = response.getServerNonce();
        
	message = new Message();
        message.appendObject(number);
        message.appendObject(pubkey);
        clientNonce = Crypto.generateNonce();
	message.appendObject(clientNonce);
	message.appendObject(serverNonce);

        response = stub.readGeneral(number, pubkey, clientNonce, serverNonce, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getAnnouncements());

	if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
		return "Signature verification failed";
	else if(response.getClientNonce() != clientNonce)
		return "Server returned invalid nonce: possible replay attack";
	else {
            	this.printAnnouncements(response.getAnnouncements());
            	return response.getStatusCode();
        }
    }

    /**
     * createAnnouncement
     *
     */
    public Announcement createAnnouncement() throws IOException, FileNotFoundException, SigningException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Write your Announcement (up to 255 characters):");
        String msg = reader.readLine();
        while(msg.length() > 255){
          System.out.println("This announcement has more than 255 characters. Please write up to 255 characters:");
          msg = reader.readLine();
        }
        //
        // pede referencias ao user, NULL sempre, por enquanto!
        //
        System.out.println("Write your references seperated by a comma in this format: pubkey:id");
        String[] splitComma = reader.readLine().split(",");
        Announcement[] refs = null;
        for (String ann : splitComma){
          //refs.add(ann.split[]);
        }

        Message message = new Message();
       	message.appendObject(this.getPublicKey());
       	message.appendObject(msg.toCharArray());
        message.appendObject(null); //refs

        byte[] signature = Crypto.sign(this.getPrivateKey(), message.getByteArray());



	    Announcement a = new Announcement(this.getPublicKey(), msg.toCharArray(), null, signature, annId);
      annId++;

        return a;
    }


    /**
     * main
     *
     */
    public static void main(String[] args) {
        String host = (args.length < 1) ? null : args[0];
        try{
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            Client cli = new Client();
            ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");
            int option = 0;
            boolean bk = false;

            while(option != 6) {
                cli.printOptions();
                option = 0;
                try {
                    option = Integer.parseInt(reader.readLine());
                } catch (Exception e) {
                    System.out.println("Exception: " + e.toString());
                    //bk = true;
                }
                switch (option) {
                    case 1:
                        System.out.println(cli.registerOption(stub));
                        break;
                    case 2:
                        System.out.println(cli.postOption(stub));
                        break;
                    case 3:
                        System.out.println(cli.postGeneralOption(stub));
                        break;
                    case 4:
                        System.out.println("Path of the Pubic key to read from: (for test -> test.pub)");
                        PublicKey pubkeyToRead = Crypto.readPublicKey("../resources/test.pub");
                        System.out.println("Number of Announcements to read: ");
                        int number = Integer.parseInt(reader.readLine());
                        System.out.println(cli.readOption(stub, number, pubkeyToRead));
                        break;
                    case 5:
                        System.out.println("Number of Announcements to read: ");
                        int number2 = Integer.parseInt(reader.readLine());
                        System.out.println(cli.readGeneralOption(stub, number2));
                        break;
                    case 6:
                        bk = true;
                        break;

                    default:
                        break;
                }
                if(bk) break;
            }
        } catch (ConnectException e) {
            System.out.println("Do not forget to turn on the server :D");
            return;
        }
        catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}
