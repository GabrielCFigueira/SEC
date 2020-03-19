package sec.dpas;

import sec.dpas.exceptions.NegativeNumberException;

import java.security.PublicKey;

import java.rmi.Remote;
import java.rmi.*;
import java.rmi.registry.*;

import java.sql.Timestamp;
import java.util.*;

/**
 * TODO!
 *
 */
public interface ServerAPI extends Remote {

    String sayHello() throws RemoteException;

    String register(PublicKey pubkey, Timestamp ts, byte[] signature) throws RemoteException;

    String post(PublicKey pubkey, char[] message, Announcement[] a) throws RemoteException;

    String postGeneral(PublicKey pubkey, char[] message, Announcement[] a) throws RemoteException;

    ArrayList<Announcement> read(PublicKey pubkey, int number)
            throws RemoteException, IndexOutOfBoundsException, IllegalArgumentException, NegativeNumberException;

    ArrayList<Announcement> readGeneral(int number)
            throws RemoteException, IndexOutOfBoundsException, IllegalArgumentException, NegativeNumberException;

}
