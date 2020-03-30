package sec.dpas;

import java.security.PublicKey;

import java.rmi.Remote;
import java.rmi.*;
import java.rmi.registry.*;

import java.util.*;

import java.io.IOException;
import java.lang.Exception;

/**
 * ServerAPI
 *
 */
public interface ServerAPI extends Remote {

    Response getNonce(PublicKey pubkey, long clientNonce, byte[] signature) throws RemoteException;

    Response register(PublicKey pubkey, long clientNonce, byte[] signature) throws RemoteException;

    Response post(PublicKey pubkey, Announcement a, long clientNonce, long serverNonce, byte[] signature) throws RemoteException;

    Response postGeneral(PublicKey pubkey, Announcement a, long clientNonce, long serverNonce, byte[] signature) throws RemoteException;

    Response read(PublicKey pubkey, int number, PublicKey senderKey, long clientNonce, long serverNonce, byte[] signature)
            throws RemoteException;

    Response readGeneral(int number, PublicKey senderKey, long clientNonce, long serverNonce, byte[] signature)
            throws RemoteException;

}
