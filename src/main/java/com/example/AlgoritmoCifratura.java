package com.example;


import java.util.Random;
import java.io.IOException;
import java.math.BigInteger;
import java.io.IOException;
public class AlgoritmoCifratura {

    //------------------------ATTRIBUTI DELLA CLASSE-------------------------\\
    private Integer x; //Numero privato per l'algoritmo di Diffie–Hellman
    private BigInteger g; //Numero casuale per l'algoritmo di Diffie–Hellman
    private BigInteger n; //Numero casuale per l'algoritmo di Diffie–Hellman
    //Chiave per derivata dall'algoritmo Diffie–Hellman
    private Integer chiave_DiffieHellman;
    //Chiavi per l'utilizzo degli algoritmi di crittografia simmetrica
    private Integer chiave1;
    private Integer chiave2;
    //Variabili di appoggio per la generazione delle chiavi
    private Integer min_val = 1; 
    private Integer max_val = 256;
    private String cod_sfida;

    /*
     *Costruttore per il server, nel momento della creazione, secondo la crittazione
     *asimmetrica di Diffie–Hellman il server(destinatario) genera un suo numero x privato   
     *
     *
     * Costruttore per il client, nel momento della creazione, secondo la crittazione
     * asimmetrica di Diffie–Hellman il client(mittente) genera un suo numero x privato 
     * e anche altri due numeri g ed n che serviranno per l'algoritmo
     */
    //------------------------COSTRUTTORE-------------------------\\
    public AlgoritmoCifratura(Boolean device){

        this.setX();
        //Se device è uguale a true, crei l'oggetto in modalità server, altrimenti, client 
        if ( device ){

            //Essendo nel server, sarà lui a generare le chiavi al momento della connessione del client
            //Queste saranno generate randomicamente e saranno diverse per ogni client connesso
            this.chiave1 = this.generaChiave();
            this.chiave2 = this.generaChiave();
            //Generiamo inoltre il codice sfida per l'autenticazione
            this.cod_sfida = this.cod_sfida();

        } 

        else{

            /*
            Essendo nel client, e stando inizializzando l'oggetto "AlgoritmoCrittografia" per la prima volta
            Generiamo i numeri g ed n dell'algoritmo di Diffie–Hellman
            */
            this.g = new BigInteger ( (int)(Math.random() * (max_val - min_val)) + "");
            this.n = new BigInteger ( (int)(Math.random() * (max_val - min_val)) + "");


        }   

    }
        //Setter delle chiavi
    //------------------------ SETTER -------------------------\\
    //Setter del numero privato dell'algoritmo di Diffie–Hellman
    public void setX(){

        this.x =((int) (Math.random() * (max_val - min_val)));
        
    }

    //Setter del numero g
    public void setG(Integer g){

        this.g = new BigInteger( g + "" );
        
    }
    //Setter del numero n
    public void setN(Integer n){

        this.n = new BigInteger( n + "" );
        
    }

    //Setter della chiave di DiffieHellman, data dal rispettivo calcolo ((g^y % n)^x) % n
    public void setChiaveDiffieHellman(Integer gx){

        this.chiave_DiffieHellman = this.calcolo_DiffieHellman( gx, this.n.intValue() );

    }
    //Setter chiave simmetrica 1
    public void setChiave1(Integer chiave1){

        this.chiave1 = chiave1;    
    
    }
    //Setter chiave simmetrica 2
    public void setChiave2(Integer chiave2){

        this.chiave2 = chiave2;    

    }

    public void setCodSfida( String cod_sfida ){

        this.cod_sfida = cod_sfida;

    }

    //------------------------ GETTER -------------------------\\
    /*
     * Metodi per ritornare i valori g ed n, che il client invierà al server
     * (Non ne creiamo uno per x, in quanto questo resta privato come numero)
     */
    public Integer getG(){

        return this.g.intValue();

    }

    public Integer getN(){

        return this.n.intValue();

    }
    //Getter della chiave simmetrica 1
    public Integer getChiave1(){

        return this.chiave1;

    }
    //Getter della chiave simmetrica 2
    public Integer getChiave2(){

        return this.chiave2;

    }
    //Getter della chiave asimmetrica 
    public Integer getChiaveDiffieHellman(){

        return this.chiave_DiffieHellman;

    }

    public String getCodSfida(){

        return this.cod_sfida;

    }

    //------------------------ METODI -------------------------\\
    //E' il metodo che permette di cifrare un messaggio 
    public String cifra(String message) {
        //Inizializzazione di una variabile di appoggio, che contiene il messaggio iniziale
        String cipher_message = message;
        /*Eseguiamo 16 ripetizioni di cifratura, in cui andiamo ad alteranare le tecniche di cifratura utilizzando
        Sia la prima che la seconda chiave!
        per un totale di : 16 * 4 = 64 operazioni di confusione 
        */

        for ( int i = 0; i < 16; i++ ){

            cipher_message = this.cifratura_shift(cipher_message,this.chiave1);
            cipher_message = this.cifratura_permutazione(cipher_message, this.chiave2);
            cipher_message = this.cifratura_shift(cipher_message, this.chiave2);
            cipher_message = this.cifratura_permutazione(cipher_message, this.chiave1);

        }
        
        return cipher_message;

    }
    //E' il metodo che permette di decifrare un messaggio 
    public String decifra(String message) {
         //Inizializzazione di una variabile di appoggio, che contiene il messaggio crittato
        String decipher_message = message;
        /*Eseguiamo le operazioni precedenti in maniera inversa per decifrare il messaggio*/
        for ( int i = 0; i < 16; i++ ){

            decipher_message = this.decifratura_permutazione(decipher_message, this.chiave1);
            decipher_message = this.decifratura_shift(decipher_message, this.chiave2);
            decipher_message = this.decifratura_permutazione(decipher_message, this.chiave2);
            decipher_message = this.decifratura_shift(decipher_message, this.chiave1);

        }
        
        return decipher_message;

    }

    /*Nel caso in cui doessimo cifrare le chiavi, in quanto non le inoltriamo in chiaro, non possiamo utilizzare
     * il metodo "cifra" in quanto chiave1 e chiave2 non sono ancora definite per entrambi, quindi eseguiamo una singola
     * ripetizione della tecnica di cifratura con shift
     */
    public String cifra_chiave( String message ){
        
        return this.cifratura_shift(message, this.chiave_DiffieHellman); 

    }   
    //Operazione inversa alla precedente per decifrare la chiave 
    public String decifra_chiave( String message ){
        
        return this.decifratura_shift(message, this.chiave_DiffieHellman); 

    }  

    /* Generiamo la chiave di crittazione, sarà un numero Intero generato randomicamente
        Che indica il numero di posizioni ASCII da sciftare del carattere della stringa da crittare/decrittare
    */ 
    public  Integer generaChiave() {
        //Queste possono essere generate con un range più ampio di valori rispetto a quella di DiffieHellman
        Integer max_val = 127;
        double randomNum = Math.random() * (max_val - min_val);

        return (int) randomNum;

    }

    //Calcoliamo (g^x % n)
    public Integer calcolo_DiffieHellman(Integer g, Integer n) {
        //Inizializziamo i due numeri interi
        BigInteger num1 = new BigInteger(g + "");
        BigInteger num2 = new BigInteger(n + "");
        //Calcoliamo la potenza g^x
        BigInteger result = num1.pow(x);
        //Successivamente al calcolo eseguiamo il modulo, ottenendo: g^x % n
        result = result.mod(num2);
        return result.intValue();

    }

    //Calcolo codice sfida
    public String cod_sfida(){
        int min = 33;
        int max = 126;
        Random c = new Random();
        //Daremo al codice uno standard del tipo  yxyx (in cui y è un numero, ed x è una cifra)
        String cod = "";
        
        //Aggiungiamo un numero generato casualmente
        cod += this.generaChiave();
        
        //Generiamo numero casuale
        int app = c.nextInt(max - min + 1) + min;
        //Lo trasformaimo in carattere
        cod += (char) (app);

        //Aggiungiamo un numero generato casualmente
        cod += this.generaChiave();

        //Generiamo numero casuale
        app = c.nextInt(max - min + 1) + min;
        //Lo trasformaimo in carattere
        cod += (char) (app);


        return cod;
    }

    // Metodo di cifratura tramite shift caratteri
    public String cifratura_shift(String message, Integer chiave) {
        
        // Creo l'array della stringa
        char[] output = new char[message.length()];

        // Converto la stringa in array di char per manipolare carattere per carattere
        output = message.toCharArray();

        // Crittiamo la stringa
        for (Integer i = 0; i < message.length(); i++) {

            // Se il carattere è uno escluso dal range, lo copiamo così com'è
            if ( ((int)output[i]) < 33 || ((int)output[i]) > 126 ) { 

                continue;

            }
            /*
             * Restringiamo il range di valori che il singolo carattere può assumere, in
             * quanto
             * nella tabella ASCII, sono presenti caratteri non rappresentabili, quindi il
             * range sarà da
             * 33 a 126
             */

            // Controlliamo che il nostro valore shiftato non superi l'ultimo valore del
            // range
            if ((output[i] + chiave) > 126) {
                // Se questo accade, facciamo operazioni aritmetiche per riportarlo all'inizio
                // del range
                //output[i] = output[((output[i] + chiave) - (126 )) + 32];
                //Proviamo prima a calcolare il carattere che dovrebbe assumere
                int final_index = ((output[i] + chiave) - (126)) + 32;
                
                //Controllo se il carattere finale, supera il range di numeri
                while( final_index > 126 ){
                    
                    //E se lo fa, lo riporto all'inizio del range
                    final_index = (final_index - 126) + (32);
                    
                }
                
                output[i] = (char)final_index;

                
            } else {
                // Altrimenti, sommiamo direttamente la chiave
                // Concasting in carattere char, del carattere ASCII (intero) shiftato
                output[i] = (char) (output[i] + chiave);

            }

            

        }

        // Ritrasformiamo in stringa
        message = "";
        for (Integer i = 0; i < output.length; i++) {

            message += output[i];

        }

        return message;

    }

    // Metodo di decifratura tramite shift caratteri
    public String decifratura_shift(String message, Integer chiave) {
        
        char[] output = new char[message.length()];
        // Converto la stringa in array di char per manipolare carattere per carattere
        output = message.toCharArray();

        // Crittiamo la stringa
        for (Integer i = 0; i < message.length(); i++) {

            // Se il carattere è ugale allo spazio, non viene crittato
            if ( ((int)output[i]) < 33 || ((int)output[i]) > 126 ) { 

                continue;

            }

            if ((output[i] - chiave) < 33) {
                
                //Proviamo prima a calcolare il carattere che dovrebbe assumere
                int final_index = ((output[i] - chiave) + (126) - (32));
                //Controllo se il carattere finale, supera (inferiormente) il range dei numeri
                
                while( final_index < 33 ){
                    
                    //Se questo accade, faccio in modo da eliminare l'eccesso ritornando al carattere corretto
                    final_index = (final_index + 126) - (32);

                }
                
                output[i] = (char)final_index ;

                //output[i] = (char) ((output[i] - chiave) + (126 ) - (32));

            } else {

                // Concasting in carattere char, del carattere ASCII (intero) shiftato
                output[i] = (char) (output[i] - chiave);

            }

        }

        // Ritrasformiamo in stringa
        message = "";
        for (Integer i = 0; i < output.length; i++) {

            message += output[i];
        }

        return message;

    }

    private String cifratura_permutazione(String message, Integer chiave) {

        char[] input = new char[message.length()];
        // Converto la stringa in array di char per manipolare carattere per carattere
        input = message.toCharArray();

        // Creiamo un array di supporto per eseguire la permutazione
        char[] output = new char[message.length()];

        // Tramite il modulo della chiave e della lunghezza della stringa, andiamo a
        // calcolare il numero
        // di volte in cui il carattere percorre l'intero array prima di trovare la
        // posizione
        Integer permutazione = (chiave % message.length());

        for (int i = 0; i < message.length(); i++) {

            if ((i + permutazione) >= (message.length())) {
                // Nel caso in cui l'indice da permutare, supera la lunghezza dell'array,
                // dobbiamo trovare a quale posizione questo vada inserito:
                /*
                 * permutazione - (int)(chiave / message.length()) -> Teniamo in conto che
                 * quando dall'utimo elemente passiamo al primo, scaliamo una posizione per ogni
                 * "ritorno all'anizio"
                 * message.length()-1) -> Per indicare l'ultima poszione
                 * - i ->Troviamo quanti posti mancano ancora da contare prima di ricominciare
                 * l'array
                 * 2 - (3-1-0) - 2
                 */ 
                output[((permutazione - ((message.length() - 1) - i)) - (1))] = input[i];

            }

            else
                output[i + permutazione] = input[i];

        }

        // Ricostruiamo la stringa finale carattere per carattere
        message = "";
        for (Integer i = 0; i < output.length; i++) {

            message += output[i];

        }
        return message;

    }

    private String decifratura_permutazione(String message, Integer chiave) {

        char[] input = new char[message.length()];
        // Converto la stringa in array di char per manipolare carattere per carattere
        input = message.toCharArray();

        // Creiamo un array di supporto per eseguire la permutazione
        char[] output = new char[message.length()];

        // Tramite il modulo della chiave e della lunghezza della stringa, andiamo a
        // calcolare il numero
        // di volte in cui il carattere percorre l'intero array prima di trovare la
        // posizione
        Integer permutazione = (chiave % message.length());

        for (int i = 0; i < message.length(); i++) {

            if ((i - permutazione) < 0) {

                /*
                 * Nel caso in cui la posizione del carattere da spostare (all'indietro questa
                 * volta) va oltre lo 0 (in negativo)
                 * Eseguiamo il seguente ragionamento:
                 * (message.length()-1) -> Poichè partiamo dall'ultima posizione dell'array
                 * 
                 * A questo, sottraiamo
                 * "permutazione" -> che indica la variabile contenete il numero di posizioni da
                 * shiftare
                 * -i -> indica il numero di posizioni che il carattere deve ancora percorrere
                 * prima di ritnrare alla fine
                 * -(int)(chiave/message.length()) -> indica il numero di ritorni alla fine
                 * dell'array
                 */
                output[(message.length() - 1) - ((permutazione - i - 1))] = input[i];
            }

            else
                output[i - permutazione] = input[i];
        }
        // Ricostruiamo la stringa finale carattere per carattere
        message = "";
        for (Integer i = 0; i < output.length; i++) {

            message += output[i];

        }
        return message;

    }
    

}
