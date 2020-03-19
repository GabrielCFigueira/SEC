package sec.dpas;

/**
 * Hello world!
 *
 */


 import java.security.Key;

 import java.io.FileNotFoundException;
 import java.io.IOException;

import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import java.util.Arrays;
import java.util.Hashtable;

public class Client
{
    private Client() {}

    private Key getPrivateKey() throws FileNotFoundException, IOException{
        return Crypto.readPrivateKey("/src/resources/test.key");
    }

    public Key getPublicKey() throws FileNotFoundException, IOException{
        return Crypto.readPublicKey("/src/resources/test.key.pub");
    }
    public static void main( String[] args )
    {
      System.out.println( "Hello Worlds!" );
      String host = null;//(args.length < 1) ? null : args[0];
      try{
        //Registry reg = LocateRegistry.getRegistry();

        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/Hello");
        //ServerAPI stub = (ServerAPI) reg.lookup("Hello");
        String response = stub.sayHello();

        System.out.println("response: " + response);
      }
      catch (Exception e) {
        System.err.println("Client exception: " + e.toString());
        e.printStackTrace();
      }
    }
}
