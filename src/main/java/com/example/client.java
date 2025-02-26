package com.example;

import java.net.Socket;
import java.util.Scanner;

import javax.xml.crypto.AlgorithmMethod;

import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;

public class client {
    
    public static void main( String[] args ){

        try {
            //----------------------INIZIALIZZAZIONE SOCKET----------------------\\
            Integer porta = 9999;
            //Ci connettiamo al server
            Socket socket = new Socket(InetAddress.getLoopbackAddress(), porta );
            System.out.println("\nConnessione al server effettuata sulla porta: " + porta + "\n" );
            //Inizializziamo i buffer input ed output del socket client
            DataInputStream buffer_input = new DataInputStream( socket.getInputStream() );
            DataOutputStream buffer_output = new DataOutputStream( socket.getOutputStream() );

            //-----------------SCAMBIAMO LE CHIAVI CON IL SERVER--------------------------\\

            /*Creiamo l'oggetto in modalità client, andando ad inizializzare le variabili
            che ci servono per la crittografia Dieff_Hellman*/
            AlgoritmoCifratura algoritmo = new AlgoritmoCifratura(false); 
            //Calcoliamo il nuero di Hellman (g^x % n)
            Integer gx = algoritmo.calcolo_DiffieHellman(algoritmo.getG(), algoritmo.getN());
            
            //Inviamo i 3 parametri al server, ovvero: n,g,(g^x % n) 
            buffer_output.writeBytes(algoritmo.getN() + "\n");
            buffer_output.writeBytes(algoritmo.getG() + "\n");
            buffer_output.writeBytes(gx + "\n");
            
            //Ci andiamo a calcolare la chiave finale ovver il numero: ((g^y % n)^x) % n
            algoritmo.setChiaveDiffieHellman(Integer.parseInt(buffer_input.readLine()));
            
            //Acquisiamo la chiave 1 crittata, la decrittiamo tramite il metodo apposito, e la andiamo a settare come attributo dell'oggetto
            algoritmo.setChiave1(Integer.parseInt(algoritmo.decifra_chiave(buffer_input.readLine())));
            //Acquisiamo la chiave 2 crittata, la decrittiamo tramite il metodo apposito, e la andiamo a settare come attributo dell'oggetto
            algoritmo.setChiave2(Integer.parseInt(algoritmo.decifra_chiave(buffer_input.readLine())));

            //Stampiamo a schermo le chiavi per scopo dimostrativo
            System.out.println("Le chiavi ottenute risultano:\n");
            System.out.println("Chiave di Diffie-Helman: " + algoritmo.getChiaveDiffieHellman() + "\n");
            System.out.println("Chiave di crittografia 1: " + algoritmo.getChiave1() + "\n");
            System.out.println("Chiave di crittografia 2: " + algoritmo.getChiave1() + "\n");

            // ------------------------ AUTENTICAZIONE -------------------------\\
            Scanner input = new Scanner(System.in);
            String message;
            Boolean login = false;

            while (!login) {

                System.out.println("1) Eseguire la registrazione \n2) Eseguire il login \n3) Esci \nRisposta:");
                message = input.nextLine();
                // Comunichiamo la scelta al server
                buffer_output.writeBytes(message + "\n");

                switch (message) {

                    case "1": {

                        System.out.println("Inserisci username: ");
                        // Acquisiamo username, lo crittografiamo e inoltriamo al server
                        buffer_output.writeBytes(algoritmo.cifra(input.nextLine()) + "\n");

                        //Acquisiamo la password, la crittografiamo, e la inoltriamo al server
                        System.out.println("Inserisci password: ");
                        buffer_output.writeBytes(algoritmo.cifra(input.nextLine()) + "\n");

                        System.out.println("Risposta del server: " + buffer_input.readLine());
                        return;
                        

                    }

                    case "2": {

                        System.out.println("Inserisci username: ");
                        // Acquisiamo username e lo inoltriamo al server
                        buffer_output.writeBytes(algoritmo.cifra(input.nextLine()) + "\n");

                        //Non inoltriamo la password in chiaro ma richiediamo il codice sfida! 
                        String cod_sfida = buffer_input.readLine();
                        //Ottenuto questo
                        System.out.println( "Il Codice Sfida risulta: " + cod_sfida + "\n" );

                        System.out.println("Inserisci password: ");
                        // Acquisiamo la password
                        String password = input.nextLine();

                        //Sommiamo a questa il codice sfida e la crittiamo 
                        String secured_password = password + cod_sfida;
                        secured_password = algoritmo.cifra((secured_password));

                        System.out.println("La password sicura risulta: " + secured_password);
                        //E la inviamo al server
                        buffer_output.writeBytes(secured_password + "\n");

                        // Aspettiamo la risposta del login:
                        message = buffer_input.readLine();

                        if (message.equals("1")) {

                            System.out.println("Login avvenuto con successo!" +"\n");
                            login = true;

                        } else
                            System.out.println("Le credenziali non corrispondono!"+"\n");
                        break;
                    }

                    case "3":
                        return;

                }

            }

            //------------------------ACQUISIZIONE DEL MESSAGGIO DA INPUT-------------------------\\
            //Classe di interazione con il System.in (ovvero l'input da tastera)
            Boolean fine = false;
            do{

                System.out.println("Inserisci la stringa da inviare al server: ");
                //Acquisiamo il messaggio del client
                message = input.nextLine();
                System.out.println("La stringa acquisita risulta: " + message + "\n");
                if ( message.equalsIgnoreCase("fine")) fine = true;

                //Crittiamo il messaggio in input,
                message = algoritmo.cifra(message);
                System.out.println("La stringa cifrata risulta: " + message + "\n");
                //Inoltriamo il messaggio al server
                buffer_output.writeBytes(message + "\n");

                if ( fine ) break;

                //Leggiamo la risposta del server:
                message = buffer_input.readLine();
                System.out.println("La stringa ricevuta dal server risulta: " + message + "\n");
                //Decifriamo il messaggio
                message = algoritmo.decifra(message);
                //visualizziamo il messaggio
                System.out.println("La stringa decifrata risulta: " + message + "\n");

                /*Teniamo la connessione aperta fra client e server, 
                fino a quando la stringa inserita dal client non è fine*/
            } while ( ! fine );

        } catch (IOException error) {
            //Nel caso la connessione o una qualsiasi operazione fallisse, restituiamo il messagio d'errore con le sue specifiche
            System.out.println("Errore nella connessione al server!: \n " + error.getMessage() );

        }





    }


}
