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

    Response getNonce(PublicKey pubkey, String clientNonce, byte[] signature) throws RemoteException;

    Response register(PublicKey pubkey, String clientNonce, byte[] signature) throws RemoteException;

    Response post(PublicKey pubkey, Announcement a, String clientNonce, String serverNonce, byte[] signature) throws RemoteException;

    Response postGeneral(PublicKey pubkey, Announcement a, String clientNonce, String serverNonce, byte[] signature) throws RemoteException;

    Response read(PublicKey pubkey, int number, PublicKey senderKey, String clientNonce, String serverNonce, byte[] signature)
            throws RemoteException;

    Response readGeneral(int number, PublicKey senderKey, String clientNonce, String serverNonce, byte[] signature)
            throws RemoteException;

    void echo(int serverId, Announcement a, byte[] signature, boolean gen) throws RemoteException;

    void ready(int serverId, Announcement a, boolean abort, byte[] signature, boolean gen) throws RemoteException;

}
