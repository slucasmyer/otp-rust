/**
 * Author: Sullivan Lucas Myer
 * -----------------------------------------
 * Encryption client for one-time pad encryption.
 * Reads ciphertext and key from respective files,
 * interleaves ciphertext and key characters,
 * and sends interleaved buffer to enc_server.
 * Receives encrypted text back from enc_server,
 * and writes it to stdout.
 * Implements an application-level handshake protocol,
 * which prevents connection to dec_server.
 * -----------------------------------------
 */

 use std::env;
 use std::fs;
 use std::io::{self, Read, Write};
 use std::net::TcpStream;
 use std::process;
 
 const CHUNK_SIZE: usize = 1000;
 const HANDSHAKE_SIGNAL: &str = "@";
 const TERMINATION_SIGNAL: &str = "@";
 
 fn main() {
     let args: Vec<String> = env::args().collect();
     if args.len() < 4 {
         eprintln!("USAGE: {} ciphertext_file key_file port", args[0]);
         process::exit(1);
     }
 
     let hostname = "0.0.0.0";
     let cipher = &args[1];
     let key = &args[2];
     let port = &args[3];
     let address = format!("{}:{}", hostname, port);
 
     
 
     let ct_buffer = read_file(&cipher).expect("Error reading ciphertext file");
     let key_buffer = read_file(&key).expect("Error reading key file");
 
     if key_buffer.len() < ct_buffer.len() {
         eprintln!("Error: Key is too short");
         process::exit(1);
     }
 
     validate_buffer(&ct_buffer).expect("Plaintext contains invalid characters");
     validate_buffer(&key_buffer).expect("Key contains invalid characters");
 
     let mut interleaved_buffer = interleave_buffers(&ct_buffer, &key_buffer);
 
     let mut stream = TcpStream::connect(address).expect("Failed to connect to server");
 
     // Handshake
     handshake(&mut stream).expect("Handshake failed");
 
     // Send and receive
     send_and_receive(&mut stream, &mut interleaved_buffer).expect("Communication error");
 
 }
 
 fn read_file(path: &str) -> io::Result<String> {
     fs::read_to_string(path)
 }
 
 fn validate_buffer(buffer: &str) -> Result<(), String> {
     let buffer = buffer.trim_end_matches('\n'); // Trim newline characters from the end
     for (i, b) in buffer.bytes().enumerate() {
         if !(b.is_ascii_uppercase() || b as char == ' ') {
             return Err(format!("Invalid character '{}' (byte: {}) at position {}", b as char, b, i));
         }
     }
     Ok(())
 }
 
 fn interleave_buffers(ct_buffer: &str, key_buffer: &str) -> String {
     ct_buffer.chars().zip(key_buffer.chars())
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
 
 fn send_and_receive(stream: &mut TcpStream, interleaved_buffer: &str) -> io::Result<()> {
     let mut offset = 0;
     while offset < interleaved_buffer.len() {
         let end = std::cmp::min(offset + CHUNK_SIZE, interleaved_buffer.len());
         let chunk = &interleaved_buffer[offset..end];
         stream.write_all(chunk.as_bytes())?;
         offset += CHUNK_SIZE;
     }
     // Send termination signal
     stream.write_all(TERMINATION_SIGNAL.as_bytes())?;
     let mut buffer = vec![0; CHUNK_SIZE];
     let n = stream.read(&mut buffer)?;
     buffer.truncate(n);
     println!("{}", String::from_utf8_lossy(&buffer));
     Ok(())
 }
 