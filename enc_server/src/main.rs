/**
 * Author: Sullivan Lucas Myer
 * -----------------------------------------
 * Encryption server for one-time pad encryption.
 * Receives interleaved plaintext and key from enc_client,
 * encrypts according to OTP protocol,
 * sends the encrypted text back to enc_client.
 * Implements an application-level handshake protocol,
 * which prevents dec_client from connecting to enc_server.
 * -----------------------------------------
 */

/*-----------USE STATEMENTS-----------*/
use std::net::TcpListener;
use std::thread;
use std::env;
use utils::handle_enc_client;
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const HOSTNAME: &str = "0.0.0.0";
const HANDSHAKE_SIGNAL: char = '$';
const TERMINATION_SIGNAL: char = '$';
/*-----------CONSTANT DEFINITIONS-----------*/

/*-----------MAIN-----------*/
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: {} port", args[0]);
        std::process::exit(1);
    }

    let port = &args[1];
    let listener = TcpListener::bind(format!("{}:{}", HOSTNAME, port)).expect("Failed to bind to port");
    println!("Server listening on port {}", port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || handle_enc_client(stream, HANDSHAKE_SIGNAL, TERMINATION_SIGNAL));
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}
/*-----------MAIN-----------*/