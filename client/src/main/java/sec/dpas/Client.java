package sec.dpas;

/**
 * Hello world!
 *
 */

import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Client
{
    private Client() {}
    public static void main( String[] args )
    {
      System.out.println( "Hello Worlds!" );
      String host = null;//(args.length < 1) ? null : args[0];
      try{
        //Registry reg = LocateRegistry.getRegistry();

        ClientAPI stub = (ClientAPI) Naming.lookup("//localhost:1099/Hello");
        //ClientAPI stub = (ClientAPI) reg.lookup("Hello");
        String response = stub.sayHello();

        System.out.println("response: " + response);
      }
      catch (Exception e) {
        System.err.println("Client exception: " + e.toString());
        e.printStackTrace();
      }
    }
}
