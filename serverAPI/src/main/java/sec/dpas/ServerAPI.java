package sec.dpas;

/**
 * Hello world!
 *
 */

import java.rmi.Remote;
import java.rmi.*;
import java.rmi.registry.*;

public interface ServerAPI extends Remote
{
    //public static void main( String[] args )
    //{
        String sayHello() throws RemoteException;

    //}
}