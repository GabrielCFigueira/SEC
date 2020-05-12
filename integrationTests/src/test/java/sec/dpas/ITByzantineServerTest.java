package sec.dpas;

import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.After;

import mockit.*;
import static org.mockito.Mockito.*;

import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.AlreadyBoundException;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.Timestamp;

import java.util.ArrayList;
import java.util.List;

import java.lang.Exception;
import sec.dpas.exceptions.SigningException;

/**
 * Client/Server Test: Read
 *
 * SimpleTestWithMocks
 * FirstReturnInvalid
 * WrongRead
 * 
 * 
 * 
 * SimpleTest4Servers4Clients
 * SimpleTest4Servers20Clients
 * SimpleTest20Servers20Clients
 */
public class ITByzantineServerTest {

    static Registry registry1, registry2, registry3, registry4;
    static ServerAPI stub1, stub2, stub3, stub4;
    private Server server1, server2, server3, server4;
    private Client client1, client2;

    @Before
    public void init() throws IOException, RemoteException, KeyStoreException, AlreadyBoundException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, NotBoundException, SigningException {
        server1 = new Server(1);
        stub1 = (ServerAPI) UnicastRemoteObject.exportObject(server1, 0);
        server2 = new Server(2);
        stub2 = (ServerAPI) UnicastRemoteObject.exportObject(server2, 0);
        server3 = new Server(3);
        stub3 = (ServerAPI) UnicastRemoteObject.exportObject(server3, 0);
        server4 = new Server(4);
        stub4 = (ServerAPI) UnicastRemoteObject.exportObject(server4, 0);

        registry1 = LocateRegistry.createRegistry(8001);
        registry1.bind("ServerAPI", stub1);
        registry2 = LocateRegistry.createRegistry(8002);
        registry2.bind("ServerAPI", stub2);
        registry3 = LocateRegistry.createRegistry(8003);
        registry3.bind("ServerAPI", stub3);
        registry4 = LocateRegistry.createRegistry(8004);
        registry4.bind("ServerAPI", stub4);

        client1 = new Client("test", "testtest", 1, 4);
        client2 = new Client("test1", "testtest1", 1, 4);

        client1.register();
        client2.register();
    }

    @After
    public void cleanup() throws RemoteException, NoSuchObjectException, NotBoundException {
        registry1.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry1, true);
        registry2.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry2, true);
        registry3.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry3, true);
        registry4.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry4, true);
        server1.cleanup();
        server2.cleanup();
        server3.cleanup();
        server4.cleanup();
    }


    @Test
    public void SimpleTestWithMocks() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {

        Server mockedServer = mock(Server.class);
        registry1.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry1, true);
        stub1 = (ServerAPI) UnicastRemoteObject.exportObject(mockedServer, 0);
        registry1 = LocateRegistry.createRegistry(8001);
        registry1.bind("ServerAPI", stub1);

        final Announcement a = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);

        when(mockedServer.getNonce(any(PublicKey.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Nonce generated", (String) i.getArgument(1), "5");
        });
        when(mockedServer.post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Announcement posted", (String) i.getArgument(2));
        });

        assertEquals("Announcement posted", client1.post(a));

    }


    @Test
    public void FirstReturnInvalid() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {

        Server mockedServer = mock(Server.class);
        registry1.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry1, true);
        stub1 = (ServerAPI) UnicastRemoteObject.exportObject(mockedServer, 0);
        registry1 = LocateRegistry.createRegistry(8001);
        registry1.bind("ServerAPI", stub1);
<<<<<<< Updated upstream
	
	final Announcement a = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);

	when(mockedServer.getNonce(any(PublicKey.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
	    return server1.constructResponse("Nonce generated", (String) i.getArgument(1), "5");
	});
	when(mockedServer.post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
	    return server1.constructResponse("Signature verification failed", (String) i.getArgument(2));
	});

	assertEquals("Announcement posted", client1.post(a));
	
=======

        final Announcement a = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);

        when(mockedServer.getNonce(any(PublicKey.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Nonce generated", (String) i.getArgument(1), "5");
        });
        when(mockedServer.post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Signature verification failed", (String) i.getArgument(2));
        }).thenAnswer(i -> {
            return server1.constructResponse("Announcement posted", (String) i.getArgument(2));
        });

        assertEquals("Announcement posted", client1.post(a));

>>>>>>> Stashed changes
    }


    @Test
    public void WrongRead() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {

        Announcement a1 = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);
        Announcement a2 = client2.createAnnouncement("Boas".toCharArray(), null, 1, false);
        assertEquals("Announcement posted", client1.post(a1));

        Server mockedServer = mock(Server.class);
        registry1.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry1, true);
        stub1 = (ServerAPI) UnicastRemoteObject.exportObject(mockedServer, 0);
        registry1 = LocateRegistry.createRegistry(8001);
        registry1.bind("ServerAPI", stub1);

<<<<<<< Updated upstream
	ArrayList<Announcement> anns2 = new ArrayList<Announcement>();
	ArrayList<Announcement> anns1 = new ArrayList<Announcement>();
	anns2.add(a2);
	anns1.add(a1);
	

	when(mockedServer.getNonce(any(PublicKey.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
	    return server1.constructResponse("Nonce generated", (String) i.getArgument(1), "5");
	});
	
	when(mockedServer.read(any(PublicKey.class), any(Integer.class), any(PublicKey.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
	    return server1.constructResponse("read successful", anns2, (String) i.getArgument(3));
	});
	
	when(mockedServer.post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
	    return server1.constructResponse("Announcement posted", (String) i.getArgument(2));
	});

	assertEquals("read successful", client1.read(0, client1.getPublicKey()));
	
=======
        ArrayList<Announcement> anns2 = new ArrayList<Announcement>();
        ArrayList<Announcement> anns1 = new ArrayList<Announcement>();
        anns2.add(a2);
        anns1.add(a1);


        when(mockedServer.getNonce(any(PublicKey.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Nonce generated", (String) i.getArgument(1), "5");
        });

        when(mockedServer.read(any(PublicKey.class), any(Integer.class), any(PublicKey.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("read successful", anns2, (String) i.getArgument(3));
        }).thenAnswer(i -> {
            return server1.constructResponse("read successful", anns1, (String) i.getArgument(3));
        });

        when(mockedServer.post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Announcement posted", (String) i.getArgument(2));
        });

        assertEquals("read successful", client1.read(0, client1.getPublicKey()));

    }


    @Test
    public void SimpleTest4Servers4Clients() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {

        /*Server mockedServer = mock(Server.class);
        registry1.unbind("ServerAPI");
        UnicastRemoteObject.unexportObject(registry1, true);
        stub1 = (ServerAPI) UnicastRemoteObject.exportObject(mockedServer, 0);
        registry1 = LocateRegistry.createRegistry(8001);
        registry1.bind("ServerAPI", stub1);*/

        //final Announcement a = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);

        client1.post("Boas".toCharArray(), null);
        assertEquals("read successful", client1.read(0, client1.getPublicKey()));
        ArrayList<Announcement> read1 = client1.getLastRead();
        for(Announcement ann : read1)
            assertEquals("Boas", ann.getMessage());
        //assertEquals("read successful", client2.read(0, client1.getPublicKey()));

        /* when(mockedServer.getNonce(any(PublicKey.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Nonce generated", (String) i.getArgument(1), "5");
        });
        when(mockedServer.post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class))).thenAnswer(i -> {
            return server1.constructResponse("Announcement posted", (String) i.getArgument(2));
        });

        assertEquals("Announcement posted", client1.post(a)); */
>>>>>>> Stashed changes
    }

}
