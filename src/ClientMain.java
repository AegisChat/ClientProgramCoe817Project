import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ClientMain {
    private static final int port = 5555;
    private static final String hostname = "localhost";

    public static void main(String[] args) {


        Scanner scanner = new Scanner(System.in);
        Socket socket = null;
        ClientConnect clientConnect = null;
        String message;
        try {
            socket = new Socket(hostname,port);
            clientConnect = new ClientConnect(socket);
            new Thread(clientConnect).start();
        } catch (IOException e) {
            e.printStackTrace();
        }


        while(true){
            message = scanner.nextLine();
            clientConnect.writeToServer(message);
        }
        //is that it? I can try connecting both now?
        //for the main ya



    }

}
