package sec.dpas;

import java.security.PublicKey;

import java.rmi.Remote;
import java.rmi.*;
import java.rmi.registry.*;

import java.sql.Timestamp;
import java.util.*;

import java.io.IOException;
import java.lang.Exception;

/**
 * TODO!
 *
 */
public interface ServerAPI extends Remote {

    Response register(PublicKey pubkey, Timestamp ts, byte[] signature) throws RemoteException;

    Response post(PublicKey pubkey, Announcement a, Timestamp ts, byte[] signature) throws RemoteException;

    Response postGeneral(PublicKey pubkey, Announcement a, Timestamp ts, byte[] signature) throws RemoteException;

    Response read(PublicKey pubkey, int number, PublicKey senderKey, Timestamp ts, byte[] signature)
            throws RemoteException, IndexOutOfBoundsException, IllegalArgumentException, IOException, ClassNotFoundException;

    Response readGeneral(int number, PublicKey senderKey, Timestamp ts, byte[] signature)
            throws RemoteException, IndexOutOfBoundsException, IllegalArgumentException, IOException, ClassNotFoundException;

}
