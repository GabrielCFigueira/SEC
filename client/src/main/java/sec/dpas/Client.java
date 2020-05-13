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
import java.util.List;
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
    private int _f = 1;
    private int _N = 4;
    private Hashtable<String, String> _servers = new Hashtable<String, String>();
    private int _timeStamp = 1;
    private int _generalBoardStamp = 0;


    private void generateUrls() {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("../resources/servers.txt"));
            String line = reader.readLine();
            ArrayList<String> lines = new ArrayList<String>();
            while(line != null) {
                lines.add(line);
                line = reader.readLine();
            }
            reader.close();

            String[] words;
            for(int i = 0; i < _N || i < lines.size() ; ++i) {
                words = lines.get(i).split(" ");
                _servers.put(words[0], words[1]);
            }
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

    public int getGeneralBoardStamp() { return _generalBoardStamp; }

    public ArrayList<Announcement> getLastRead() { return _lastRead; }

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
    public void printAnnouncements(List<Announcement> anns) {
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
        messageReceived.appendObject(response.getAnnouncements());
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
        messageReceived.appendObject(response.getAnnouncements());
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
        messageReceived.appendObject(response.getAnnouncements());
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
    public String readOption(ServerAPI stub, PublicKey serverpubkey, int number, PublicKey pubkeyToRead, List<ArrayList<Announcement>> readList) throws IOException, SigningException {
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
        messageReceived.appendObject(response.getAnnouncements());
        messageReceived.appendObject(response.getClientNonce());

        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else {
            for(Announcement a : response.getAnnouncements())
                if(!verifyAnnouncement(a, pubkeyToRead, false))
                    return "Signature verification failed";
            synchronized(readList) {
                readList.add(response.getAnnouncements());
            }
            return response.getStatusCode();
        }
    }

    /**
     * readGeneralOption
     *
     */
    public String readGeneralOption(ServerAPI stub, PublicKey serverpubkey, int number, List<ArrayList<Announcement>> readList) throws IOException, SigningException {
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
        messageReceived.appendObject(response.getAnnouncements());
        messageReceived.appendObject(response.getClientNonce());

        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else {
            for(Announcement a : response.getAnnouncements())
                if(!verifyAnnouncement(a, a.getKey(), true))
                    return "Signature verification failed";
            synchronized(readList) {
                readList.add(response.getAnnouncements());
            }
            return response.getStatusCode();
        }
    }

    //here be distributed section
    public String register() throws IOException, FileNotFoundException, SigningException {
        String url, id;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        Hashtable<String, Future<String>> responses = new Hashtable<String, Future<String>>();
        
	for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            responses.put(id, threadpool.submit(() -> registerOption(stub, serverpubkey)));
        }

        return asyncCall(responses, "User registered", threadpool);

    }

    public String post(Announcement a) throws IOException, FileNotFoundException, SigningException {
        String url, id;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        Hashtable<String, Future<String>> responses = new Hashtable<String, Future<String>>();
        
    	for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            responses.put(id, threadpool.submit(() -> postOption(stub, serverpubkey, a)));
        }
        return asyncCall(responses, "Announcement posted", threadpool);
    }

    public String post(char[] msg, ArrayList<Announcement> refs) throws IOException, FileNotFoundException, SigningException {
        return this.post(this.createAnnouncement(msg, refs, _timeStamp++, false));
    }

    public String postGeneral(Announcement a) throws IOException, FileNotFoundException, SigningException {
        String url, id;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        Hashtable<String, Future<String>> responses = new Hashtable<String, Future<String>>();
        
    	for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            responses.put(id, threadpool.submit(() -> postGeneralOption(stub, serverpubkey, a)));
        }
        return asyncCall(responses, "General announcement posted", threadpool);
    }

    public String postGeneral(char[] msg, ArrayList<Announcement> refs) throws IOException, FileNotFoundException, SigningException {
        readGeneral(0);
        Announcement a = this.createAnnouncement(msg, refs, _generalBoardStamp, true);
        return postGeneral(a);
    }

    public String read(int number, PublicKey pubkeyToRead) throws IOException, FileNotFoundException, SigningException {
        String url, id, status;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        Hashtable<String, Future<String>> responses = new Hashtable<String, Future<String>>();
	ArrayList<ArrayList<Announcement>> readList = new ArrayList<ArrayList<Announcement>>();
        
	for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
	    } catch (Exception e) {
                e.printStackTrace();
                continue;
            }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            responses.put(id, threadpool.submit(() -> readOption(stub, serverpubkey, 0, pubkeyToRead, readList)));
	}
        status = asyncCall(responses, "read successful", threadpool);

	if (!status.equals("read successful"))
	    return status;
	
	List<Announcement> anns = getMaxTimeStampList((ArrayList<ArrayList<Announcement>>) readList.clone());

        this.printAnnouncements(anns);
        for(int i = 0; i < anns.size(); i++)
            post(anns.get(i));

        return status;
    }

    private int getMaxTimeStamp(ArrayList<Announcement> readList) {
	int stamp = 0;
	for(Announcement a : readList)
	    if(stamp < a.getTimeStamp())
		stamp = a.getTimeStamp();
    	return stamp;
    }

    private ArrayList<Announcement> getMaxTimeStampList(ArrayList<ArrayList<Announcement>> readList) {
	ArrayList<Announcement> max = new ArrayList<Announcement>();
	int stamp = 0;
	for(ArrayList<Announcement> read : readList) {
	    if(read.get(read.size() - 1).getTimeStamp() > stamp) {
	        stamp = read.get(read.size() - 1).getTimeStamp();
	    	max = read;
	    }
	}
	_lastRead = max;
    	return max;
    }

    public String readGeneral(int number) throws IOException, FileNotFoundException, SigningException {
        String url, id, status;
        ExecutorService threadpool = Executors.newCachedThreadPool();
        Hashtable<String, Future<String>> responses = new Hashtable<String, Future<String>>();
	ArrayList<ArrayList<Announcement>> readList = new ArrayList<ArrayList<Announcement>>();
        
	for(Enumeration<String> ids = _servers.keys(); ids.hasMoreElements();) {
            id = ids.nextElement();
            url = _servers.get(id);
            final ServerAPI stub;
            try {
                stub = (ServerAPI) Naming.lookup(url);
	    } catch (Exception e) {
                e.printStackTrace();
                continue;
	    }
            final PublicKey serverpubkey = Crypto.readPublicKey("../resources/server" + id + ".pub");
            responses.put(id, threadpool.submit(() -> readGeneralOption(stub, serverpubkey, 0, readList)));
	}
        status = asyncCall(responses, "read successful", threadpool);

	if (!status.equals("read successful"))
	    return status;
	
	ArrayList<Announcement> anns = getMaxTimeStampList((ArrayList<ArrayList<Announcement>>) readList.clone());
        this.printAnnouncements(anns);
	_generalBoardStamp = getMaxTimeStamp(anns) + 1;

        return status;
    }


    /*
     * Async Call
     *
     */
    public String asyncCall(Hashtable<String, Future<String>> responses, String expectedCode, ExecutorService threadpool) {
        String id;
        int nResponses = 0;
	int majority = Math.round((((float) _N) +_f) / 2);
        String status = "";
        boolean error = false;

        while (nResponses < majority) {
            for(Enumeration<String> ids = responses.keys(); ids.hasMoreElements();) {
                id = ids.nextElement();
                if(responses.get(id).isDone()) {
		    nResponses++;
                    try {
                        if(responses.get(id).get().equals(expectedCode) || status.equals(""))
			    status = responses.get(id).get(); 
                    } catch (Exception e) {
                        System.out.println(e.getMessage() + " : Our Async got exception.");
                    }
                    responses.remove(id);
                }
            }
            try {
                Thread.sleep(100);
            } catch(Exception e) {
                System.out.println("sleep exception");
            }
        }

        threadpool.shutdown();

        return status;
        //return responses;
    }

    /**
     * createAnnouncement
     *
     */
    public Announcement createAnnouncement(int timeStamp, boolean isGeneralBoard) throws IOException, FileNotFoundException, SigningException {
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


        return createAnnouncement(msg.toCharArray(), refs, timeStamp, isGeneralBoard);
    }

    public Announcement createAnnouncement() throws IOException, FileNotFoundException, SigningException{
        return createAnnouncement(_timeStamp++, false);
    }

    public Announcement createAnnouncement(char[] msg, ArrayList<Announcement> refs, int timeStamp, boolean isGeneralBoard) throws IOException, FileNotFoundException, SigningException {

        Message message = new Message();
        message.appendObject(this.getPublicKey());
        message.appendObject(msg);
        message.appendObject(refs);
        String id = String.valueOf(_clientId) + ":" + String.valueOf(_annId);
        message.appendObject(id);
        message.appendObject(timeStamp);
        message.appendObject(isGeneralBoard);
        byte[] signature = Crypto.sign(this.getPrivateKey(), message.getByteArray());

        _annId++;
        return new Announcement(this.getPublicKey(), msg, refs, signature, id, timeStamp, isGeneralBoard);
    }

    public boolean verifyAnnouncement(Announcement a, PublicKey key, boolean expected) throws IOException, FileNotFoundException {

        Message message = new Message();
        message.appendObject(a.getKey());
        message.appendObject(a.getMessage());
        message.appendObject(a.getReferences());
        message.appendObject(a.getId());
        message.appendObject(a.getTimeStamp());
        message.appendObject(a.isGeneralBoard());
        if(expected != a.isGeneralBoard())
            return false;
        return Crypto.verifySignature(key, message.getByteArray(), a.getSignature());
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
            Announcement a = null;
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
                            a = cli.createAnnouncement();
                            System.out.println(cli.post(a));
                            break;
                        case 3:
                            cli.readGeneral(0);
                            a = cli.createAnnouncement(cli.getGeneralBoardStamp(), true);
                            System.out.println(cli.postGeneral(a));
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
