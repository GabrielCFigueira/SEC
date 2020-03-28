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
import java.sql.Timestamp;
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

    private Client() throws FileNotFoundException, IOException {
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

    private PrivateKey getPrivateKey() throws FileNotFoundException, IOException{ return _privKey; }

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
        System.out.println("Announcements");
        System.out.println(anns);
    }

    /**
     * registerOption
     *
     */
    public String registerOption(ServerAPI stub) throws IOException, FileNotFoundException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();
        Message message = new Message();
        Timestamp ts = new Timestamp(System.currentTimeMillis());

        message.appendObject(pubkey);
        message.appendObject(ts);

        // call function from ServerAPI
        Response response = stub.register(pubkey, ts, Crypto.sign(privkey, message.getByteArray()));

        // verificacao da assinatura da response
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");
        Message messageReceived = new Message();

        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getTimestamp());

        if(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature())) {
            return response.getStatusCode();
        }
        return "Signature verification failed";
    }

    /**
     * postOption
     *
     */
    public String postOption(ServerAPI stub) throws IOException, FileNotFoundException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        // creating Announcement
        Announcement a = this.createAnnouncement();

        // creating Message
        Message message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        message.appendObject(ts);

        // call post from ServerAPI
        Response response = stub.post(pubkey, a, ts, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getTimestamp());

        if(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature())) {
            return response.getStatusCode();
        }
        return "Signature verification failed";
    }

    /**
     * postGeneralOption
     *
     */
    public String postGeneralOption(ServerAPI stub) throws IOException, FileNotFoundException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        // creating Announcement
        Announcement a = this.createAnnouncement();

        // creating Message
        Message message = new Message();
        message.appendObject(pubkey);
        message.appendObject(a);
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        message.appendObject(ts);

        // call post from ServerAPI
        Response response = stub.postGeneral(pubkey, a, ts, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getTimestamp());

        if(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature())) {
            return response.getStatusCode();
        }
        return "Signature verification failed";
    }

    /**
     * readOption
     *
     */
    public String readOption(ServerAPI stub, int number, PublicKey pubkeyToRead) throws IOException, FileNotFoundException, SigningException, ClassNotFoundException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        Message message = new Message();
        message.appendObject(pubkey);
        message.appendObject(number);
        message.appendObject(pubkeyToRead);
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        message.appendObject(ts);

        Response response = stub.read(pubkeyToRead, number, pubkey, ts, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getTimestamp());
        messageReceived.appendObject(response.getAnnouncements());

        if(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature())) {
            this.printAnnouncements(response.getAnnouncements());
            return response.getStatusCode();
        }
        return "Signature verification failed";
    }

    /**
     * readGeneralOption
     *
     */
    public String readGeneralOption(ServerAPI stub, int number) throws IOException, FileNotFoundException, SigningException, ClassNotFoundException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        Message message = new Message();
        message.appendObject(number);
        message.appendObject(pubkey);
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        message.appendObject(ts);

        Response response = stub.readGeneral(number, pubkey, ts, Crypto.sign(privkey, message.getByteArray()));

        // response signature verification
        PublicKey serverpubkey = Crypto.readPublicKey("../resources/server.pub");

        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getTimestamp());
        messageReceived.appendObject(response.getAnnouncements());

        if(Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature())) {
            this.printAnnouncements(response.getAnnouncements());
            return response.getStatusCode();
        }
        return "Signature verification failed";
    }

    /**
     * createAnnouncement
     *
     */
    public Announcement createAnnouncement() throws IOException, FileNotFoundException, SigningException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in)); 
        System.out.println("Write your Announcement:");
        String msg = reader.readLine();
        //
        // pede referencias ao user, NULL sempre, por enquanto!
        //

        Message message = new Message();
       	message.appendObject(this.getPublicKey());
       	message.appendObject(msg.toCharArray());
        message.appendObject(null); //refs

        byte[] signature = Crypto.sign(this.getPrivateKey(), message.getByteArray());
        
	    Announcement a = new Announcement(this.getPublicKey(), msg.toCharArray(), null, signature);

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
                        System.out.println("Number of Announcements to read?");
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
