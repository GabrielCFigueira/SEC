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

    public int getGeneralBoardStamp() { return _generalBoardStamp; }

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
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getAnnouncements());

        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else {
	    for(Announcement a : response.getAnnouncements())
		if(!verifyAnnouncement(a))
	    	    return "Signature verification failed";
            this.printAnnouncements(response.getAnnouncements());
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
        messageReceived.appendObject(response.getClientNonce());
        messageReceived.appendObject(response.getAnnouncements());

        if(!Crypto.verifySignature(serverpubkey, messageReceived.getByteArray(), response.getSignature()))
            return "Signature verification failed";
        else if(!clientNonce.equals(response.getClientNonce()))
            return "Server returned invalid nonce: possible replay attack";
        else {
	    for(Announcement a : response.getAnnouncements())
		if(!verifyAnnouncement(a))
	    	    return "Signature verification failed";
            this.printAnnouncements(response.getAnnouncements());
	    synchronized(readList) {
		readList.add(response.getAnnouncements());
	    }
            return response.getStatusCode();
        }
    }

    //here be distributed section
    public String register() throws IOException, FileNotFoundException, SigningException {
        String url, id;
        ExecutorService threadpool;
        Hashtable<String, Future<String>> responses;
	while (true) {
	    threadpool = Executors.newCachedThreadPool();
	    responses = new Hashtable<String, Future<String>>();
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

            String status = asyncCall(responses, "User registered", threadpool);
	    if (!status.equals("Try again"))
	    	return status;
	}
	
    }

    public String post(Announcement a) throws IOException, FileNotFoundException, SigningException {
        String url, id;
        ExecutorService threadpool;
        Hashtable<String, Future<String>> responses;
	while (true) {
	    threadpool = Executors.newCachedThreadPool();
	    responses = new Hashtable<String, Future<String>>();
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
            String status = asyncCall(responses, "Announcement posted", threadpool);
	    if (!status.equals("Try again"))
	    	return status;
	}
    }

    public String post(char[] msg, ArrayList<Announcement> refs) throws IOException, FileNotFoundException, SigningException {
	    return this.post(this.createAnnouncement(msg, refs, _timeStamp++));
    }

    public String postGeneral(Announcement a) throws IOException, FileNotFoundException, SigningException {
        String url, id;
        ExecutorService threadpool;
        Hashtable<String, Future<String>> responses;
	while (true) {
	    threadpool = Executors.newCachedThreadPool();
	    responses = new Hashtable<String, Future<String>>();
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
            String status = asyncCall(responses, "General announcement posted", threadpool);
	    if (!status.equals("Try again"))
	    	return status;
	}
    }

    public String postGeneral(char[] msg, ArrayList<Announcement> refs) throws IOException, FileNotFoundException, SigningException {
	readGeneral(0);
	Announcement a = this.createAnnouncement(msg, refs, _generalBoardStamp);
	return postGeneral(a);
    }

    public String read(int number, PublicKey pubkeyToRead) throws IOException, FileNotFoundException, SigningException {
        String url, id, status;
        ExecutorService threadpool;
        Hashtable<String, Future<String>> responses;
	List<ArrayList<Announcement>> readList;
	while (true) {
	    threadpool = Executors.newCachedThreadPool();
	    responses = new Hashtable<String, Future<String>>();
	    ArrayList<ArrayList<Announcement>> tempReadList = new ArrayList<ArrayList<Announcement>>();
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
            	responses.put(id, threadpool.submit(() -> readOption(stub, serverpubkey, 0, pubkeyToRead, tempReadList)));
	    }
            status = asyncCall(responses, "read successful", threadpool);
	    readList = (List<ArrayList<Announcement>>) tempReadList.clone();
	    if (!status.equals("Try again"))
	    	break;
	}

	if (!status.equals("read successful"))
	    return status;
	
	List<Announcement> anns = getMaxTimeStamp(readList);

	for(int i = 0; i < anns.size(); i++)
	    post(anns.get(i));

        return status;
    }

    private List<Announcement> getMaxTimeStamp(List<ArrayList<Announcement>> readList) {
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
        ExecutorService threadpool;
        Hashtable<String, Future<String>> responses;
	List<ArrayList<Announcement>> readList;
	while (true) {
	    threadpool = Executors.newCachedThreadPool();
	    responses = new Hashtable<String, Future<String>>();
	    ArrayList<ArrayList<Announcement>> tempReadList = new ArrayList<ArrayList<Announcement>>();
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
            	responses.put(id, threadpool.submit(() -> readGeneralOption(stub, serverpubkey, 0, tempReadList)));
	    }
            status = asyncCall(responses, "read successful", threadpool);
	    readList = (List<ArrayList<Announcement>>) tempReadList.clone();
	    if (!status.equals("Try again"))
	    	break;
	}

	if (!status.equals("read successful"))
	    return status;
	
	List<Announcement> anns = getMaxTimeStamp(readList);
	_generalBoardStamp = anns.size() + 1;

	return status;
    }


    /*
     * Async Call
     *
     */
    public String asyncCall(Hashtable<String, Future<String>> responses, String expectedCode, ExecutorService threadpool) {
    //public Hashtable<String, Future<String>> asyncCall(Hashtable<String, Future<String>> responses, ExecutorService threadpool) {
        String id;
        int majority = 2 * _f + 1;
        int nResponses = 0;
        String status = "";
	boolean error = false;

        while (nResponses < majority) {
            for(Enumeration<String> ids = responses.keys(); ids.hasMoreElements();) {
            	id = ids.nextElement();
                if(responses.get(id).isDone()) {
                    try {
                        if(responses.get(id).get().equals(expectedCode)) {
                            // necessario mudar este if para abrangir mais hipoteses
			    status = responses.get(id).get(); 
	 		    nResponses++;
                        } else {
			    if (status != "")
		      		return "Try again";
			    status = responses.get(id).get();
			    expectedCode = status;
			}
                    } catch (Exception e) {
                        System.out.println("Our Async got exception.");
                    }
                    responses.remove(id);
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

        return status;
        //return responses;
    }

    /**
     * createAnnouncement
     *
     */
    public Announcement createAnnouncement(int timeStamp) throws IOException, FileNotFoundException, SigningException {
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


        return createAnnouncement(msg.toCharArray(), refs, timeStamp);
    }

    public Announcement createAnnouncement() throws IOException, FileNotFoundException, SigningException{
	    return createAnnouncement(_timeStamp++);
    }

    public Announcement createAnnouncement(char[] msg, ArrayList<Announcement> refs, int timeStamp) throws IOException, FileNotFoundException, SigningException {

        Message message = new Message();
        message.appendObject(this.getPublicKey());
        message.appendObject(msg);
        message.appendObject(refs);
        String id = String.valueOf(_clientId) + ":" + String.valueOf(_annId);
	message.appendObject(id);
	message.appendObject(timeStamp);
	byte[] signature = Crypto.sign(this.getPrivateKey(), message.getByteArray());

        _annId++;
        return new Announcement(this.getPublicKey(), msg, refs, signature, id, timeStamp);
    }

    public boolean verifyAnnouncement(Announcement a) throws IOException, FileNotFoundException {
	
        Message message = new Message();
        message.appendObject(this.getPublicKey());
        message.appendObject(a.getMessage());
        message.appendObject(a.getReferences());
	message.appendObject(a.getId());
	message.appendObject(a.getTimeStamp());
	return Crypto.verifySignature(a.getKey(), message.getByteArray(), a.getSignature());
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
			    a = cli.createAnnouncement();
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
