/**
 * Author: Sullivan Lucas Myer
 * -----------------------------------------
 * Decryption client for one-time pad encryption.
 * Reads ciphertext and key from respective files,
 * interleaves ciphertext and key characters,
 * and sends interleaved buffer to dec_server.
 * Receives decrypted text back from dec_server,
 * and writes it to stdout.
 * Implements an application-level handshake protocol,
 * which prevents connection to enc_server.
 * -----------------------------------------
 */

/*-----------USE STATEMENTS-----------*/
use std::env::args;
use std::net::TcpStream;
use std::process::exit;
use utils::{
    read_file,
    validate_buffer,
    interleave_buffers,
    client_handshake,
    send_and_receive
};
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const HOSTNAME: &str = "0.0.0.0";
const HANDSHAKE_SIGNAL: &str = "@";
const TERMINATION_SIGNAL: &str = "@";
/*-----------CONSTANT DEFINITIONS-----------*/
 
/*-----------MAIN-----------*/
 fn main() {
    /*-----------CHECK ARGS-----------*/
    let args: Vec<String> = args().collect();
    if args.len() < 4 {
        eprintln!("USAGE: {} ciphertext_file key_file port", args[0]);
        exit(1);
    }
    /*-----------CHECK ARGS-----------*/

    /*-----------INITIALIZE-----------*/
    let cipher = &args[1];
    let key = &args[2];
    let port = &args[3];
    let address = format!("{}:{}", HOSTNAME, port);
    /*-----------INITIALIZE-----------*/
    
    /*-----------READ & VALIDATE INPUT-----------*/
    let mut ct_buffer = read_file(&cipher).expect("Error reading ciphertext file");
    let mut key_buffer = read_file(&key).expect("Error reading key file");

    ct_buffer = ct_buffer.trim_end_matches('\n').to_string();
    key_buffer = key_buffer.trim_end_matches('\n').to_string();

    if key_buffer.len() < ct_buffer.len() {
        eprintln!("Error: Key is too short");
        exit(1);
    }

    validate_buffer(&ct_buffer).expect("Plaintext contains invalid characters");
    validate_buffer(&key_buffer).expect("Key contains invalid characters");
    /*-----------READ & VALIDATE INPUT-----------*/

    /*-----------INTERLEAVE BUFFERS-----------*/
    let mut interleaved_buffer = interleave_buffers(&ct_buffer, &key_buffer);
    /*-----------INTERLEAVE BUFFERS-----------*/

    /*-----------CONNECT TO SERVER-----------*/
    let mut stream = TcpStream::connect(address).expect("Failed to connect to server");
    /*-----------CONNECT TO SERVER-----------*/

    /*-----------HANDSHAKE-----------*/
    client_handshake(&mut stream, HANDSHAKE_SIGNAL).expect("Handshake failed");
    /*-----------HANDSHAKE-----------*/
    
    /*-----------SEND & RECEIVE-----------*/
    send_and_receive(&mut stream, &mut interleaved_buffer, TERMINATION_SIGNAL).expect("Communication error");
    /*-----------SEND & RECEIVE-----------*/

}
/*-----------MAIN-----------*/