/**
 * Author: Sullivan Lucas Myer
 * -----------------------------------------
 * Decryption server for one-time pad encryption.
 * Receives interleaved ciphertext and key from dec_client,
 * decrypts according to OTP protocol,
 * sends the decrypted text back to dec_client.
 * Implements an application-level handshake protocol,
 * which prevents enc_client from connecting to dec_server.
 * -----------------------------------------
 */

/*-----------USE STATEMENTS-----------*/
use std::net::TcpListener;
use std::process::exit;
use std::thread::spawn;
use std::env::args;
use utils::handle_dec_client;
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const HOSTNAME: &str = "0.0.0.0";
const HANDSHAKE_SIGNAL: char = '@';
const TERMINATION_SIGNAL: char = '@';
/*-----------CONSTANT DEFINITIONS-----------*/

/*-----------MAIN-----------*/
fn main() {
    let args: Vec<String> = args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: {} port", args[0]);
        exit(1);
    }

    let port = &args[1];
    let listener = TcpListener::bind(format!("{}:{}", HOSTNAME, port)).expect("Failed to bind to port");
    println!("Server listening on port {}", port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                spawn(move || handle_dec_client(stream, HANDSHAKE_SIGNAL, TERMINATION_SIGNAL));
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}
/*-----------MAIN-----------*/