package com.example;

public class mainServer {
    
    public static void main( String[] args ){

        //Porta di creazione del server
        Integer porta = 9999;
        //Creo l'oggetto server
        ServerMultiThread server = new ServerMultiThread(porta);
        //Richiamo la funzione listen, metto il server in ascolto di nuove richieste
        server.listen();

    }

}
