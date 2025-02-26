package com.example;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerMultiThread {
    
    //Dichiariamo gli elementi che ci serviranno per la realizzazione del socket del server
    private ServerSocket connection_socket;
    private Socket data_socket;
    private Integer porta;
    private Integer nThread; //Indica il numero di thread gestiti dal server
    //Costruttore del server
    public ServerMultiThread(Integer porta){

        //Inizializziamo la variabile che contiene la porta del connection socket del server
        this.porta = porta;
        this.nThread = 0; //Inizializzazione del server, non gestisce ancora nessuna connessione

    }

    public void listen(){
        
        try{

            //Inizializziamo il connection socket, con un nuovo oggetto Serversocket creato sulla porta indicata
            connection_socket = new ServerSocket(porta);
            System.out.println("Connection socket Inizializzato!\n");
            
            //Ciclo per gestire l'ascolto continui di client sulla porta del server
            while(true){
                
                System.out.println("Sono in ascolto sulla porta: " + this.porta + "!\n");
                //Il server si metterà in ascolto delle richieste del client, e creerà il socket solo quando un client ha richiesto l'accesso al server
                data_socket = connection_socket.accept();
                //Un client si è connesso, incrementiamo il numero di client che il server sta gestendo
                this.nThread ++;
                //Nel momento in cui un client si connette, creiamo il nuovo thread che gestirà la comunicazione con il server
                ServerThread server_thread = new ServerThread(data_socket, nThread);  
                //Il metodo start dell'oggetto, richiama il nostro metodo run Overrideato
                server_thread.start();

            }
            

           

        }
        catch(IOException error){

            System.out.println("Errore nella creazione del Data Socket!: \n " + error.getMessage() );

        }


    }


}
