/**
 * Author: Sullivan Lucas Myer
 * -----------------------------------------
 * Encryption client for one-time pad encryption.
 * Reads plaintext and key from respective files,
 * interleaves plaintext and key characters,
 * and sends interleaved buffer to enc_server.
 * Receives encrypted text back from enc_server,
 * and writes it to stdout.
 * Implements an application-level handshake protocol,
 * which prevents connection to dec_server.
 * -----------------------------------------
 */

/*-----------USE STATEMENTS-----------*/
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process;
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const CHUNK_SIZE: usize = 1000;
const HANDSHAKE_SIGNAL: &str = "$";
const TERMINATION_SIGNAL: &str = "$";
/*-----------CONSTANT DEFINITIONS-----------*/

/*-----------UTILITY FUNCTIONS-----------*/
fn read_file(path: &str) -> io::Result<String> {
    fs::read_to_string(path)
}

fn validate_buffer(buffer: &str) -> Result<(), String> {
    for (i, b) in buffer.bytes().enumerate() {
        if !(b.is_ascii_uppercase() || b as char == ' ') {
            return Err(format!("Invalid character '{}' (byte: {}) at position {}", b as char, b, i));
        }
    }
    Ok(())
}

fn interleave_buffers(pt_buffer: &str, key_buffer: &str) -> String {
    pt_buffer.chars().zip(key_buffer.chars())
        .flat_map(|(pt_char, key_char)| vec![pt_char, key_char])
        .collect()
}

fn handshake(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(HANDSHAKE_SIGNAL.as_bytes())?;
    let mut response = [0; 1];
    stream.read_exact(&mut response)?;
    if response == HANDSHAKE_SIGNAL.as_bytes() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Server rejected handshake"))
    }
}

fn send_and_receive(mut stream: &TcpStream, interleaved_buffer: &str) -> io::Result<()> {
    let mut offset = 0;
    let mut buffer = [0u8; CHUNK_SIZE];
    let interleaved_length = interleaved_buffer.len();
    let mut all_sent = false;
    let mut chars_read = 0;

    loop {
        if offset < interleaved_length { // if there is still data to send
            let end = std::cmp::min(offset + CHUNK_SIZE, interleaved_length); // end of the chunk
            let chunk = &interleaved_buffer[offset..end]; // get the chunk
            stream.write_all(chunk.as_bytes())?; // send the chunk
            offset += CHUNK_SIZE; // move the offset
        }
        
        if offset >= interleaved_length && !all_sent { //all data sent
            stream.write_all(TERMINATION_SIGNAL.as_bytes())?; // send termination signal
            all_sent = true; // set all_sent to true so we don't send the termination signal again
        }
        
        print!("{}", String::from_utf8_lossy(&buffer[..chars_read])); // print the buffer
        
        buffer = [0u8; CHUNK_SIZE]; // clear buffer

        chars_read = stream.read(&mut buffer)?; // read from the stream

        if chars_read > 0 { // if we read something

            if buffer.contains(&TERMINATION_SIGNAL.as_bytes()[0]) { // if the received data contains the termination signal
                // replace the termination signal with a null byte
                for i in 0..chars_read { // iterate through the buffer
                    if buffer[i] == TERMINATION_SIGNAL.as_bytes()[0] { // if the current byte is the termination signal
                        buffer[i] = 0; // replace it with a null byte
                    }
                }
                println!("{}", String::from_utf8_lossy(&buffer[..chars_read-1])); // print the buffer
                break; // break the loop
            }
        }
    }

    Ok(())
}

/*-----------UTILITY FUNCTIONS-----------*/

/*-----------MAIN-----------*/
fn main() {
    /*-----------CHECK ARGS-----------*/
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("USAGE: {} plaintext_file key_file port", args[0]);
        process::exit(1);
    }
    /*-----------CHECK ARGS-----------*/

    /*-----------INITIALIZE-----------*/
    let hostname = "0.0.0.0";
    let plain = &args[1];
    let key = &args[2];
    let port = &args[3];
    let address = format!("{}:{}", hostname, port);
    /*-----------INITIALIZE-----------*/

    /*-----------READ & VALIDATE INPUT-----------*/
    let mut pt_buffer = read_file(&plain).expect("Error reading plaintext file");
    let mut key_buffer = read_file(&key).expect("Error reading key file");

    pt_buffer = pt_buffer.trim_end_matches('\n').to_string();
    key_buffer = key_buffer.trim_end_matches('\n').to_string();

    if key_buffer.len() < pt_buffer.len() {
        eprintln!("Error: Key is too short");
        process::exit(1);
    }

    validate_buffer(&pt_buffer).expect("Plaintext contains invalid characters");
    validate_buffer(&key_buffer).expect("Key contains invalid characters");
    /*-----------READ & VALIDATE INPUT-----------*/

    /*-----------INTERLEAVE BUFFERS-----------*/
    let mut interleaved_buffer = interleave_buffers(&pt_buffer, &key_buffer);
    /*-----------INTERLEAVE BUFFERS-----------*/

    /*-----------CONNECT TO SERVER-----------*/
    let mut stream = TcpStream::connect(address).expect("Failed to connect to server");
    /*-----------CONNECT TO SERVER-----------*/

    /*-----------HANDSHAKE-----------*/
    handshake(&mut stream).expect("Handshake failed");
    /*-----------HANDSHAKE-----------*/

    /*-----------SEND & RECEIVE-----------*/
    send_and_receive(&mut stream, &mut interleaved_buffer).expect("Communication error");
    /*-----------SEND & RECEIVE-----------*/

}
/*-----------MAIN-----------*/