package com.example;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

//La classe estende la classe Thread in quanto overrida il metodo run di esecuzione del thread
public class ServerThread extends Thread{

    private DataInputStream buffer_input;
    private DataOutputStream buffer_output;
    private Socket data_socket;
    private Integer nThread;
    //Costruttore del nuovo thread che gestirà la comunicazione con il client
    public ServerThread( Socket data_socket, Integer nThread ){
        
        try{
            //Inizializziamo il numero del thread
            this.nThread = nThread; 
            //Inizializziamo il data socket della comunicazione
            this.data_socket = data_socket;
            //Gli stream dati, derivano dai relativi metodi getter del socket: 
            //Buffer di input, dal quale il server legge i dati (lo stream) in ingresso 
            buffer_input = new DataInputStream(data_socket.getInputStream());
            //Buffer di output, nel quale il server scrive i dati (lo stream) elaborati
            buffer_output = new DataOutputStream(data_socket.getOutputStream());
            System.out.println("DataStream Inizializzati!\n");

        }
        //Nel caso il programma vada in errore, stampiamo il relativo messaggio
        catch(IOException error){

            System.out.println("Errore nella creazione del Data Socket!: \n " + error.getMessage() );

        }

       

    }

    //Corpo dell'esecuzione del thread, tramite ovverride del metodo run della superclasse Thread
    @Override
    public void run(){

        //Codice del server
        try {

            //Creiamo l'oggetto in modalità server, andando ad inizializzare le variabili
            AlgoritmoCifratura algoritmo = new AlgoritmoCifratura(true);
            
            //Riceviamo in ordine n,g,(g^x % n)
            //Essendo che il flusso di byte fra client e server è una stringa, la convertiamo in intero
            //ed usiamo gli opportuni setter, per inizializzare i valori
            algoritmo.setN(Integer.parseInt(buffer_input.readLine()));
            algoritmo.setG(Integer.parseInt(buffer_input.readLine()));
            Integer gx = Integer.parseInt(buffer_input.readLine());
            //Calcolo (g^y % n) del server
            Integer gy = algoritmo.calcolo_DiffieHellman(algoritmo.getG(), algoritmo.getN());
            //E lo mando al client
            buffer_output.writeBytes(gy + "\n");

            //Ci andiamo a calcolare la chiave finale ovvero il numero: ((g^x % n)^y) % n
            algoritmo.setChiaveDiffieHellman(gx);

            /*Una volta che possiediamo la chiave sincrona possiamo adesso crittare le altre due chiavi che 
            utilizzeremo per svolgere le varie operazioni di crittografia, e mandarle al client (NON IN CHIARO)*/
            //Inoltriamo la prima chiave crittata
            System.out.println("Chiave1 decifratura: " + algoritmo.getChiave1());
            buffer_output.writeBytes( algoritmo.cifra_chiave(algoritmo.getChiave1()+"") + "\n");
            //Inoltriamo la seconda chiave crittata
            System.out.println("Chiave2 decifratura: " + algoritmo.getChiave2());
            buffer_output.writeBytes( algoritmo.cifra_chiave(algoritmo.getChiave2()+"") + "\n");

            //Stampiamo a schermo le chiavi per scopo dimostrativo
            System.out.println("Le chiavi ottenute risultano:\n");
            System.out.println("Chiave di Diffie-Helman: " + algoritmo.getChiaveDiffieHellman() + "\n");
            System.out.println("Chiave di crittografia 1: " + algoritmo.getChiave1() + "\n");
            System.out.println("Chiave di crittografia 2: " + algoritmo.getChiave1() + "\n");

            // ------------------------ AUTENTICAZIONE -------------------------\\
            // Classe di interazione con il System.in (ovvero l'input da tastera)
            Scanner input = new Scanner(System.in);
            String message;
            
            Boolean login = false; //Variabile di controllo del login utente
            
            // Riceviamo la risposta dal client
            message = buffer_input.readLine();
            while (!login) {

                switch (message) {

                    case "1": {
                        //Inizializziamo la classe di gestione del file (simuliamo un database contenente email e password)
                        DataBase database = new DataBase('A');
                        //Acquisiamo l'username crittografato, e lo decrittografiamo
                        String username = algoritmo.decifra(buffer_input.readLine());
                        //Acquisiamo la password crittografata, e la decrittografiamo
                        String password = algoritmo.decifra(buffer_input.readLine());
                        
                        database.toFile(username, password);
                        System.out.println("Registrazione avvenuta con successo, i dati sono stati aggiunti al database!\n");
                        buffer_output.writeBytes("Registrazione avvenuta con successo!" + "\n"); 
                        //Chiudiamo il file
                        database.closeFile();
                        return;
                        
                    }

                    case "2": {

                        
                        DataBase database = new DataBase('R'); //Oggetto per la gestione dell'interazione con il file
                        
                        //Acquisisco l'username dall'utente
                        String username = algoritmo.decifra(buffer_input.readLine());
                        System.out.println("Codice Sfida Inoltrato al client:" + algoritmo.getCodSfida() + "\n" );
                        //Inoltriamo il codice sfida poichè servirà per rendere sicura la password
                        buffer_output.writeBytes(algoritmo.getCodSfida() + "\n");
                        
                        //Password del client
                        String secured_password = buffer_input.readLine();
                        
                        /*Ottenuti username e "hash" della password dal client, 
                        cerchiamo queste credenziali nel nostro database
                        */

                        // Acquisiamo la stringa da file
                        String tmp = database.fromFile();
                        while (tmp != null) {
                            /*Suddividiamo la riga letta da file, nel formato username:password
                             * in un array che conterrà l'username in posizione 0
                             * e la password in posizione 1
                             */
                            String[] split = tmp.split(":");
                            
                            //Mi calcolo l'hash della password (posizione 1 dell'array) salvata nel server
                            String hash = algoritmo.cifra(split[1]+algoritmo.getCodSfida());
                            /*
                             * Controllo se le credenziali corrispondono
                             * controllando se l'username inoltrato è uguale a quello inserito nel database
                             * E controllo se l'hash calcolato dal server precedentemente, è uguale a quello inolstrato
                             * dal client
                             */
                            
                            if (username.equals(split[0]) && secured_password.equals((hash))) {
                                //Se corrispondono il login è avvenuto con successo!
                                System.out.println("LOGIN AVVENUTO CON SUCCESSO! \n");
                                login = true;
                                //Inoltriamo il codice del login avvenuto con successo al client
                                buffer_output.writeBytes("1" + "\n");
                                break;
                            }

                            tmp = database.fromFile();

                        }

                        if (!login) {

                            System.out.println("USERNAME O PASSWORD ERRATI!\n");
                            //Inoltriamo il codice del login fallito al client
                            buffer_output.writeBytes("2" + "\n");

                        }

                        break;

                    }

                    case "3": {
                        return;
                    }

                }
            }

            //------------------------INTERAZIONE CON IL CLIENT-------------------------\\

            do{
                System.out.println("--- Conunicazione Thread n." + nThread + "! ---" + "\n");
                //Leggiamo la risposta del client:
                message = buffer_input.readLine();
                System.out.println("La stringa ricevuta risulta: " + message + "\n");
                //Decifriamo il messaggio
                message = algoritmo.decifra(message);
                //visualizziamo il messaggio
                System.out.println("La stringa decifrata risulta: " + message);

                if ( message.equalsIgnoreCase("fine") ) break;
                
                System.out.println("Messaggio di risposta: " );
                //Acquisiamo il messaggio del server
                message = input.nextLine();
                System.out.println("La stringa acquisita risulta: " + message + "\n");
                //Crittiamo il messaggio,
                message = algoritmo.cifra(message);
                System.out.println("La stringa cifrata risulta: " + message + "\n");
                //Inoltriamo il messaggio al client
                buffer_output.writeBytes(message + "\n");

                

                /*Teniamo la connessione aperta fra client e server, 
                fino a quando la stringa inserita dal client non è fine*/
            } while ( ! message.equalsIgnoreCase("fine") );

            //Richiamiamo la funzione di chiusura della connessione 
            this.close();

        } catch (IOException error) {
           
            System.out.println("Errore nel recupero dei dati!: \n " + error.getMessage() );
            
        }

    }

    public void close(){

        
        try {
            //Chiudiamo (eliminando dalla memoria) tutti gli oggetti della connessione
            data_socket.close();
            buffer_input.close();
            buffer_output.close();

        } catch (IOException error) {

            System.out.println("Errore nella chiusura del server!: \n " + error.getMessage() );
            
        }

    }


}

