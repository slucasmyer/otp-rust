/*-----------USE STATEMENTS-----------*/
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const CHUNK_SIZE: usize = 1000;
/*-----------CONSTANT DEFINITIONS-----------*/

// pub fn add(left: usize, right: usize) -> usize {
//     left + right
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }

pub fn read_file(path: &str) -> io::Result<String> {
    fs::read_to_string(path)
}

pub fn validate_buffer(buffer: &str) -> Result<(), String> {
    let buffer = buffer.trim_end_matches('\n'); // Trim newline characters from the end
    for (i, b) in buffer.bytes().enumerate() {
        if !(b.is_ascii_uppercase() || b as char == ' ') {
            return Err(format!("Invalid character '{}' (byte: {}) at position {}", b as char, b, i));
        }
    }
    Ok(())
}

pub fn interleave_buffers(ct_buffer: &str, key_buffer: &str) -> String {
    ct_buffer.chars().zip(key_buffer.chars())
        .flat_map(|(pt_char, key_char)| vec![pt_char, key_char])
        .collect()
}

pub fn client_handshake(stream: &mut TcpStream, shake_sig: &str) -> io::Result<()> {
    stream.write_all(shake_sig.as_bytes())?;
    let mut response = [0; 1];
    stream.read_exact(&mut response)?;
    if response == shake_sig.as_bytes() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Server rejected handshake"))
    }
}

pub fn send_and_receive(mut stream: &TcpStream, interleaved_buffer: &str, term_sig: &str) -> io::Result<()> {
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
            stream.write_all(term_sig.as_bytes())?; // send termination signal
            all_sent = true; // set all_sent to true so we don't send the termination signal again
        }
        
        print!("{}", String::from_utf8_lossy(&buffer[..chars_read])); // print the buffer
        
        buffer = [0u8; CHUNK_SIZE]; // clear buffer

        chars_read = stream.read(&mut buffer)?; // read from the stream

        if chars_read > 0 { // if we read something

            if buffer.contains(&term_sig.as_bytes()[0]) { // if the received data contains the termination signal
                // replace the termination signal with a null byte
                for i in 0..chars_read { // iterate through the buffer
                    if buffer[i] == term_sig.as_bytes()[0] { // if the current byte is the termination signal
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