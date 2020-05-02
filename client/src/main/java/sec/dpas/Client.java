package sec.dpas;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileReader;

import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.ConnectException;

import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
    private int _annId;
    private int _clientId;
    private static int _counter = 0;
    private ArrayList<Announcement> _lastRead;
    private int _f = 0;
    private int _N = 1;
    private Hashtable<String, String> _servers = new Hashtable<String, String>();

    private void generateUrls() {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("../resources/servers.txt"));
            String line = reader.readLine();
            String[] words;
            while (line != null) {
                words = line.split(" ");
                _servers.put(words[0], words[1]);
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

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

        _annId = 0;
        _clientId = _counter;
        _counter++;
        _lastRead = new ArrayList<Announcement>();
        generateUrls();
    }

    public Client(int f, int N ) throws FileNotFoundException, IOException {
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

        _annId = 0;
        _clientId = _counter;
        _counter++;
        _lastRead = new ArrayList<Announcement>();
        _f = f;
        _N = N;
        generateUrls();
    }

    public Client(String keyName, String password) throws FileNotFoundException, IOException {
        try {
            _privKey = Crypto.readPrivateKey("../resources/key.store", keyName, _keystorePassword, password);
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

        _annId = 0;
        _clientId = _counter;
        _counter++;
        _lastRead = new ArrayList<Announcement>();
        generateUrls();
    }

    public Client(String keyName, String password, int f, int N) throws FileNotFoundException, IOException {
        try {
            _privKey = Crypto.readPrivateKey("../resources/key.store", keyName, _keystorePassword, password);
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

        _annId = 0;
        _clientId = _counter;
        _counter++;
        _lastRead = new ArrayList<Announcement>();
        _f = f;
        _N = N;
        generateUrls();
    }

    protected PrivateKey getPrivateKey() throws FileNotFoundException, IOException{ return _privKey; }

    public PublicKey getPublicKey() throws FileNotFoundException, IOException{ return _pubkey; }

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
        System.out.println("#===============#");
        System.out.println("| Announcements |");
        System.out.println("#===============#");
        for (Announcement ann: anns){
            System.out.println("----------------------------");
            System.out.println("Announcement: " + ann.getId());
            System.out.println("Message: " + String.valueOf(ann.getMessage()));
            System.out.println("References: " + ann.getReferences());
            System.out.println("----------------------------");
        }
    }

    /**
     * registerOption
     *
     */
    public String registerOption(ServerAPI stub, PublicKey serverpubkey) throws IOException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        // create message to send to server
        Message message = new Message();
        String clientNonce = Crypto.generateNonce();
        message.appendObject(pubkey);
        message.appendObject(clientNonce);

        // call function from ServerAPI
        Response response = stub.register(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));

        // verificacao da assinatura da response
        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());

        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        
        return response.getStatusCode();
    }

    /**
     * postOption
     *
     */
    public String postOption(ServerAPI stub, PublicKey serverpubkey, Announcement a) throws IOException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        //requesting nonce
        Message message = new Message();
        message.appendObject(pubkey);
        String clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        //response signature verification

        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else if(!(response.getStatusCode().equals("Nonce generated")))
            return response.getStatusCode();
        String serverNonce = response.getServerNonce();

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
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else
            return response.getStatusCode();
    }

    /**
     * postGeneralOption
     *
     */
    public String postGeneralOption(ServerAPI stub, PublicKey serverpubkey, Announcement a) throws IOException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        //requesting nonce
        Message message = new Message();
        message.appendObject(pubkey);
        String clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        //response signature verification
        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else if(!(response.getStatusCode().equals("Nonce generated")))
            return response.getStatusCode();
        String serverNonce = response.getServerNonce();

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
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else
            return response.getStatusCode();
    }

    /**
     * readOption
     *
     */
    public String readOption(ServerAPI stub, PublicKey serverpubkey, int number, PublicKey pubkeyToRead) throws IOException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        //requesting nonce
        Message message = new Message();
        message.appendObject(pubkey);
        String clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        //response signature verification
        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else if(!(response.getStatusCode().equals("Nonce generated")))
            return response.getStatusCode();
        String serverNonce = response.getServerNonce();

        message = new Message();
        message.appendObject(pubkeyToRead);
        message.appendObject(number);
        message.appendObject(pubkey);
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
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else {
            this.printAnnouncements(response.getAnnouncements());
            _lastRead = response.getAnnouncements();
            return response.getStatusCode();
        }
    }

    /**
     * readGeneralOption
     *
     */
    public String readGeneralOption(ServerAPI stub, PublicKey serverpubkey, int number) throws IOException, SigningException {
        PublicKey pubkey = this.getPublicKey();
        PrivateKey privkey = this.getPrivateKey();

        //requesting nonce
        Message message = new Message();
        message.appendObject(pubkey);
        String clientNonce = Crypto.generateNonce();
        message.appendObject(clientNonce);
        Response response = stub.getNonce(pubkey, clientNonce, Crypto.sign(privkey, message.getByteArray()));
        //response signature verification
        Message messageReceived = new Message();
        messageReceived.appendObject(response.getStatusCode());
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getServerNonce());
        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else if(!(response.getStatusCode().equals("Nonce generated")))
            return response.getStatusCode();
        String serverNonce = response.getServerNonce();

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
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else {
            this.printAnnouncements(response.getAnnouncements());
            _lastRead = response.getAnnouncements();
            return response.getStatusCode();
        }
    }

    //here be distributed section
    public String register() throws IOException, FileNotFoundException, SigningException {
        String status = "";
        String url, id;

        int majority = _N;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        ArrayList<Future<String>> responses = new ArrayList<Future<String>>();

        for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                status += id + ": " + url + " : " + e.getMessage() + "\n";
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");

            responses.add(threadpool.submit(() -> registerOption(stub, serverpubkey)));
        }

        /*
         * Async Call
         * 
         */
        int nResponses = 0;
        while (nResponses < majority) {
            status = "";
            for(int i = responses.size()-1; i >= 0; --i) {
                if(responses.get(i).isDone()) {
                    try {
                        if(!responses.get(i).get().equals("Signature verification failed") && !responses.get(i).get().equals("Server returned invalid nonce: possible replay attack")) {
                            nResponses++;
                            status += i + ": " + _servers.get(i) + " : " + responses.get(i).get() + "\n";
                            //esta aqui um erro por causa de ids e urls
                        }
                    } catch (Exception e) {
                        System.out.println("Our Async get exception.");
                    }
                    responses.remove(i);
                }
            }
            try {
                Thread.sleep(100);
            } catch(Exception e) {
                System.out.println("sleep exception");
            }
            System.out.println("FutureTask is not finished yet..."); 
        }

        threadpool.shutdown();
        /*
         * End of Async Call
         * 
         */

        return status;
    }

    public String post() throws IOException, FileNotFoundException, SigningException {
        String status = "";
        String url, id;
        final Announcement a = this.createAnnouncement();

        int majority = 2 * _f + 1;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        ArrayList<Future<String>> responses = new ArrayList<Future<String>>();

        for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                status += id + ": " + url + " : " + e.getMessage() + "\n";
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");

            responses.add(threadpool.submit(() -> postOption(stub, serverpubkey, a)));
        }

        /*
         * Async Call
         * 
         */
        int nResponses = 0;
        while (nResponses < majority) {
            status = "";
            for(int i = responses.size()-1; i >= 0; --i) {
                if(responses.get(i).isDone()) {
                    try {
                        if(!responses.get(i).get().equals("Signature verification failed") && !responses.get(i).get().equals("Server returned invalid nonce: possible replay attack")) {
                            nResponses++;
                            status += i + ": " + _servers.get(i) + " : " + responses.get(i).get() + "\n";
                            //esta aqui um erro por causa de ids e urls
                        }
                    } catch (Exception e) {
                        System.out.println("Our Async get exception.");
                    }
                    responses.remove(i);
                }
            }
            try {
                Thread.sleep(100);
            } catch(Exception e) {
                System.out.println("sleep exception");
            }
            System.out.println("FutureTask is not finished yet..."); 
        }

        threadpool.shutdown();
        /*
         * End of Async Call
         * 
         */

        return status;
    }

    public String postGeneral() throws IOException, FileNotFoundException, SigningException {
        String status = "";
        String url, id;
        Announcement a = this.createAnnouncement();

        int majority = 2 * _f + 1;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        ArrayList<Future<String>> responses = new ArrayList<Future<String>>();

        for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                status += id + ":" + url + " : " + e.getMessage() + "\n";
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");

            responses.add(threadpool.submit(() -> postGeneralOption(stub, serverpubkey, a)));
        }

        /*
         * Async Call
         * 
         */
        int nResponses = 0;
        while (nResponses < majority) {
            status = "";
            for(int i = responses.size()-1; i >= 0; --i) {
                if(responses.get(i).isDone()) {
                    try {
                        if(!responses.get(i).get().equals("Signature verification failed") && !responses.get(i).get().equals("Server returned invalid nonce: possible replay attack")) {
                            nResponses++;
                            status += i + ": " + _servers.get(i) + " : " + responses.get(i).get() + "\n";
                            //esta aqui um erro por causa de ids e urls
                        }
                    } catch (Exception e) {
                        System.out.println("Our Async get exception.");
                    }
                    responses.remove(i);
                }
            }
            try {
                Thread.sleep(100);
            } catch(Exception e) {
                System.out.println("sleep exception");
            }
            System.out.println("FutureTask is not finished yet..."); 
        }

        threadpool.shutdown();
        /*
         * End of Async Call
         * 
         */

        return status;
    }

    public String read(int number, PublicKey pubkeyToRead) throws IOException, FileNotFoundException, SigningException {
        String status = "";
        ServerAPI stub = null;
        String url, id;
        for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                status += id + ": " + url + " : " + e.getMessage() + "\n";
                e.printStackTrace();
                continue;
            }
            PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            status += id + ": " + url + " : " + readOption(stub, serverpubkey, number, pubkeyToRead) + "\n";
        }
        return status;
    }

    public String readGeneral(int number) throws IOException, FileNotFoundException, SigningException {
        String status = "";
        ServerAPI stub = null;
        String url, id;
        for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                status += id + ": " + url + " : " + e.getMessage() + "\n";
                e.printStackTrace();
                continue;
            }
            PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            status += id + ": " + url + " : " + readGeneralOption(stub, serverpubkey, number) + "\n";
        }
        return status;
    }

    static class AsyncAnswer {
        final String value;

        AsyncAnswer(String value) {
            this.value = value;
        }
    }

    /**
     * createAnnouncement
     *
     */
    public Announcement createAnnouncement() throws IOException, FileNotFoundException, SigningException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("#=====================================================#");
        System.out.println("| Write your Announcement Body (up to 255 characters) |");
        System.out.println("#=====================================================#");
        String msg = reader.readLine();
        while(msg.length() > 255){
            System.out.println("#=====================================================#");
            System.out.println("| This Announcement Body has more than 255 characters |");
            System.out.println("| Please write up to 255 characters                   |");
            System.out.println("#=====================================================#");
            msg = reader.readLine();
        }
        //
        // pede referencias ao user, NULL sempre, por enquanto!
        //
        System.out.println("#======================================================================#");
        System.out.println("| Write your references seperated by a comma in this format: pubkey:id |");
        System.out.println("#======================================================================#");
        String[] splitComma = reader.readLine().split(",");
        ArrayList<Announcement> refs = new ArrayList<Announcement>();
        for (String id : splitComma){
            for (Announcement ann : _lastRead) {
                System.out.println(ann.getId());
                if(ann.getId().equals(id)){
                    refs.add(ann);
                }
            }
        }
        if(refs.size() == 0) refs = null;

        Message message = new Message();
        message.appendObject(this.getPublicKey());
        message.appendObject(msg.toCharArray());
        message.appendObject(refs);

        byte[] signature = Crypto.sign(this.getPrivateKey(), message.getByteArray());

        String id = String.valueOf(_clientId) + ":" + String.valueOf(_annId);
        _annId++;
        Announcement a = new Announcement(this.getPublicKey(), msg.toCharArray(), refs, signature, id);

        return a;
    }


    /**
     * main
     *
     */
    public static void main(String[] args) {
        //String host = (args.length < 1) ? null : args[0];
        try{
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            Client cli;

            if(args.length > 0)
                cli = new Client(args[0], args[1]);
            else
                cli = new Client();

            int option = 0;
            boolean bk = false;
            ServerAPI stub = null;
            while(option != 6) {
                try {
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
                            System.out.println(cli.register());
                            break;
                        case 2:
                            System.out.println(cli.post());
                            break;
                        case 3:
                            System.out.println(cli.postGeneral());
                            break;
                        case 4:
                            System.out.println("#===============================================#");
                            System.out.println("| Public key name to read from: (test or test1) |");
                            System.out.println("#===============================================#");
                            String keyName = reader.readLine();
                            while (!(keyName.equals("test")) && !(keyName.equals("test1")) ){
                                System.out.println("#===============================================#");
                                System.out.println("| Public key name to read from: (test or test1) |");
                                System.out.println("#===============================================#");
                                System.out.print(keyName);
                                keyName = reader.readLine();
                            }
                            PublicKey pubkeyToRead = Crypto.readPublicKey("../resources/" + keyName + ".pub");

                            System.out.println("#=================================#");
                            System.out.println("| Number of Announcements to read |");
                            System.out.println("#=================================#");
                            int number = Integer.parseInt(reader.readLine());
                            System.out.println(cli.read(number, pubkeyToRead));
                            break;
                        case 5:
                            System.out.println("#=================================#");
                            System.out.println("| Number of Announcements to read |");
                            System.out.println("#=================================#");
                            int number2 = Integer.parseInt(reader.readLine());
                            System.out.println(cli.readGeneral(number2));
                            break;
                        case 6:
                            bk = true;
                            break;

                        default:
                            break;
                    }
                    if(bk) break;

                } catch (ConnectException e) {
                    System.out.println("Do not forget to turn on the server :D");
                    System.out.println("Retrying connection...");
                    Thread.sleep(1000);
                    stub = (ServerAPI) Naming.lookup("//localhost:1099/ServerAPI");
                    option = 0;
                    bk = false;
                }
            }
        } catch (Exception e) {
            System.err.println("Client exception: " + e.toString());
            e.printStackTrace();
        }
    }
}
