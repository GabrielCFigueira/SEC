package sec.dpas;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
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
 * 
 * 
 * 
 */
public class ITDistributedTest {

    static Registry registry1, registry2, registry3, registry4;
    static ServerAPI stub1, stub2, stub3, stub4;
    private Server server1, server2, server3, server4;
    private Client client1, client2;
    private PublicKey pubkey1, pubkey2;

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

        pubkey1 = Crypto.readPublicKey("../resources/test.pub");
        pubkey2 = Crypto.readPublicKey("../resources/test1.pub");
        
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
    public void SimpleTest() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {
    	
	assertEquals("Announcement posted", client1.post("Ola".toCharArray(),null));
	assertEquals("Announcement posted", client2.post("Ola".toCharArray(),null));
    }

    @Test
    public void BulkTest() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {
    	
        Announcement a1 = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);
        Announcement a2 = client1.createAnnouncement("Adeus".toCharArray(), null, 2, false);
        Announcement a3 = client1.createAnnouncement("Sup".toCharArray(), null, 3, false);
        Announcement a4 = client1.createAnnouncement("Olha".toCharArray(), null, 4, false);
        Announcement a5 = client1.createAnnouncement("OOpsie".toCharArray(), null, 5, false);
        Announcement a6 = client1.createAnnouncement("oof".toCharArray(), null, 6, false);

        Announcement a7 = client2.createAnnouncement("Boas".toCharArray(), null, 1, false);
        Announcement a8 = client2.createAnnouncement("Adeus".toCharArray(), null, 2, false);
        Announcement a9 = client2.createAnnouncement("Sup".toCharArray(), null, 3, false);
        Announcement a10 = client2.createAnnouncement("Olha".toCharArray(), null, 4, false);
        Announcement a11 = client2.createAnnouncement("OOpsie".toCharArray(), null, 5, false);
        Announcement a12 = client2.createAnnouncement("oof".toCharArray(), null, 6, false);

	assertEquals("Announcement posted", client1.post(a1));
	assertEquals("Announcement posted", client1.post(a2));
	assertEquals("Announcement posted", client1.post(a3));
	assertEquals("Announcement posted", client1.post(a4));
	assertEquals("Announcement posted", client1.post(a5));
	assertEquals("Announcement posted", client1.post(a6));
	assertEquals("Announcement posted", client2.post(a7));
	assertEquals("Announcement posted", client2.post(a8));
	assertEquals("Announcement posted", client2.post(a9));
	assertEquals("Announcement posted", client2.post(a10));
	assertEquals("Announcement posted", client2.post(a11));
	assertEquals("Announcement posted", client2.post(a12));

	
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client2.postGeneral("Ola".toCharArray(),null));
	
	
	assertEquals("read successful", client1.read(0, pubkey1));
	assertEquals(6, client1.getLastRead().size());
	assertEquals("read successful", client2.read(0, pubkey1));
	assertEquals(6, client2.getLastRead().size());
	assertEquals("read successful", client2.read(0, pubkey2));	
	assertEquals(6, client2.getLastRead().size());
	
	assertEquals("read successful", client1.readGeneral(0));
	assertEquals(14, client1.getLastRead().size());
	assertEquals("read successful", client2.readGeneral(0));
	assertEquals(14, client1.getLastRead().size());
    }

    @Test
    public void WriteBack() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception, InterruptedException {
	// kick server1
        
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
	assertEquals("read successful", client1.read(0, pubkey1));
	verify(mockedServer, times(2)).post(any(PublicKey.class), any(Announcement.class), any(String.class), any(String.class), any(byte[].class));
    }


    @Test
    public void ReadBeforeWrite() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {	
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));
	assertEquals("General announcement posted", client1.postGeneral("Ola".toCharArray(),null));


	assertEquals("read successful", client2.readGeneral(0));
	assertEquals(4, client2.getGeneralBoardStamp());
    }

    
    @Test
    public void TestRegisterBroadcast() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {		
	client1 = new Client("server30", "server30", 2, 3);
        assertEquals("User registered", client1.register());

        PublicKey pubkey3 = Crypto.readPublicKey("../resources/server30.pub");
	assertTrue(server4.hasPublicKey(pubkey3));

    }

    @Test
    public void TestPostBroadcast() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {		
	client1 = new Client("test", "testtest", 2, 3);
        final Announcement a = client1.createAnnouncement("Boas".toCharArray(), null, 1, false);
        assertEquals("Announcement posted", client1.post(a));

	assertEquals(1, server4.getUserAnnouncements(pubkey1).size());

    }

    @Test
    public void TestGeneralPostBroadcast() throws IOException, RemoteException, SigningException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, Exception {		
	client1 = new Client("test", "testtest", 2, 3);
        assertEquals("General announcement posted", client1.postGeneral("Bom dia".toCharArray(), null));

	assertEquals(1, server4.getGenAnnouncements().size());

    }
}
