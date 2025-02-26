
package com.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class DataBase {

    private Character mode; // Modalità del canale aperto R = read | W = write
    private BufferedReader reader; // Oggetto per la lettura
    private BufferedWriter writer; // Oggetto per la scrittura
    private String filename = "database.txt"; // Nome del file su cui risiedono le credenziali

    public DataBase(Character mode) throws IOException {
        // Necessitiamo di sapere la modalità di apertura del file, ed il nome del file
        // da aprire
        this.mode = 'R';

        if (mode == 'W' || mode == 'w') {

            this.mode = 'W';
            this.writer = new BufferedWriter(new FileWriter(filename));

        }

        else if (mode == 'A' || mode == 'a') {

            this.mode = 'A';
            this.writer = new BufferedWriter(new FileWriter(filename, true));

        }

        else {

            this.reader = new BufferedReader(new FileReader(filename));

        }
        
    }

    // Metodo per registrarsi sul database
    public void toFile(String username, String password) throws IOException {

        String record = username + ":" + password;
        this.writer.write(record);
        this.writer.newLine();

    }

    public String fromFile() throws IOException {

        String tmp;

        tmp = this.reader.readLine();
        return tmp;

    }

    public void closeFile() throws IOException {

        if (this.mode == 'R')
            this.reader.close();
        else
            this.writer.close();

    }

}
