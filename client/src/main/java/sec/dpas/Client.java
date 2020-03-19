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
    private Key _privKey;
    private Key _pubkey;

    private Client() throws FileNotFoundException, IOException{
      _privKey = Crypto.readPrivateKey("/src/resources/test.key");
      _pubkey = Crypto.readPublicKey("/src/resources/test.key.pub");
    }



    private Key getPrivateKey() throws FileNotFoundException, IOException{
        return _privKey;
    }

    public Key getPublicKey() throws FileNotFoundException, IOException{
        return _pubkey;
    }
    public static void main( String[] args )
    {
      System.out.println( "Hello Worlds!" );
      String host = null;//(args.length < 1) ? null : args[0];
      try{
        //Registry reg = LocateRegistry.getRegistry();
        Client cli = new Client();
        ServerAPI stub = (ServerAPI) Naming.lookup("//localhost:1099/Hello");
        //ServerAPI stub = (ServerAPI) reg.lookup("Hello");
      //  String response = stub.sayHello();
        String response = stub.register(cli.getPublicKey());

        System.out.println("response: " + response);
      }
      catch (Exception e) {
        System.err.println("Client exception: " + e.toString());
        e.printStackTrace();
      }
    }
}
