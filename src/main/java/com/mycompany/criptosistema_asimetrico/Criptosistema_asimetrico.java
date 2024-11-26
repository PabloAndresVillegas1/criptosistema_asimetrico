package com.mycompany.criptosistema_asimetrico;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.PrivateKey;

public class Criptosistema_asimetrico {

    public static void main(String[] args) {
        try {
            // Proceso para generar claves
            KeyPair claves = generarClaves();
            System.out.println("Claves generadas exitosamente.");

            // Mensaje que se requiere cifrar
            String mensaje = "Hola, mi nombre es Pablo Andres y este es un mensaje cifrado.";

            // Proceso para cifrar el mensaje
            byte[] mensajeCifrado = cifrarMensaje(mensaje, claves.getPublic());
            System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));

            // Proceso para descifrar el mensaje
            String mensajeDescifrado = descifrarMensaje(mensajeCifrado, claves.getPrivate());
            System.out.println("Mensaje descifrado: " + mensajeDescifrado);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    // Función para generar las claves
    public static KeyPair generarClaves() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // Función para cifrar el mensaje
    public static byte[] cifrarMensaje(String mensaje, PublicKey clavePublica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica);
        return cipher.doFinal(mensaje.getBytes());
    }

    // Función para descifrar el mensaje
    public static String descifrarMensaje(byte[] mensajeCifrado, PrivateKey clavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada);
        byte[] bytesDescifrados = cipher.doFinal(mensajeCifrado);
        return new String(bytesDescifrados);
    }
}