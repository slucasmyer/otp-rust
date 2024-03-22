/*-----------USE STATEMENTS-----------*/
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const CHUNK_SIZE: usize = 1000;
/*-----------CONSTANT DEFINITIONS-----------*/

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

fn server_handshake(stream: &mut TcpStream, shake_sig: char) -> io::Result<()> {
    let mut handshake_buffer = [0; 1];
    stream.read_exact(&mut handshake_buffer)?;

    if handshake_buffer[0] as char != shake_sig {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Handshake failed"));
    }

    stream.write_all(&(shake_sig as u8).to_be_bytes())?;
    Ok(())
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

fn convert_to_num(c: char) -> i32 {
    match c {
        ' ' => 26,
        'A'..='Z' => c as i32 - 'A' as i32,
        _ => -1, // Indicate an invalid character (shouldn't happen with valid input)
    }
}

fn convert_to_char(n: i32) -> char {
    match n {
        0..=25 => (n as u8 + 'A' as u8) as char,
        26 => ' ',
        _ => '?', // Indicate an error (shouldn't happen with valid input)
    }
}

fn decrypt_data(data: &[u8], write_buffer: &mut [u8], mut dangling_ct_char: Option<char>, term_sig: char) -> (Option<char>, usize) {
    let mut write_index = 0;
    let mut i = 0;

    /*-----------HANDLE DANGLING CHARACTER-----------*/
    if let Some(ct_char) = dangling_ct_char {
        if !data.is_empty() {
            let key_char = data[0] as char;
            let ct_val = convert_to_num(ct_char);
            let key_val = convert_to_num(key_char);
            let decrypted_val = (ct_val - key_val + 27) % 27;
            write_buffer[write_index] = convert_to_char(decrypted_val) as u8;
            write_index += 1;
            i = 1; // Skip the first character as it's already used
            dangling_ct_char = None;
        } else {
            dangling_ct_char = Some(ct_char);
        }
    }
    /*-----------HANDLE DANGLING CHARACTER-----------*/

    /*-----------DECRYPT TCP BUFFER CONTENT-----------*/
    while i < data.len() {
        if i + 1 < data.len() && data[i] as char != term_sig {
            let ct_char = data[i] as char;
            let key_char = data[i + 1] as char;
            let ct_val = convert_to_num(ct_char);
            let key_val = convert_to_num(key_char);
            let decrypted_val = (ct_val - key_val + 27) % 27;
            write_buffer[write_index] = convert_to_char(decrypted_val) as u8;
            write_index += 1;
            i += 2;
        } else {
            // Handle dangling character or termination character
            if i + 1 >= data.len() && data[i] as char != term_sig {
                dangling_ct_char = Some(data[i] as char);
            }
            break;
        }
    }
    /*-----------DECRYPT TCP BUFFER CONTENT-----------*/

    // Ensure the write_buffer is only filled up to write_index
    for idx in write_index..write_buffer.len() {
        write_buffer[idx] = 0; // You might choose to leave as is, based on how it's used downstream
    }

    (dangling_ct_char, write_index)
}

fn encrypt_data(data: &[u8], write_buffer: &mut [u8], mut dangling_pt_char: Option<char>, term_sig: char) -> (Option<char>, usize) {
    let mut write_index = 0;
    let mut i = 0;

    /*-----------HANDLE DANGLING CHARACTER-----------*/
    if let Some(pt_char) = dangling_pt_char {
        if !data.is_empty() {
            let key_char = data[0] as char;
            let pt_val = convert_to_num(pt_char);
            let key_val = convert_to_num(key_char);
            let encrypted_val = (pt_val + key_val) % 27;
            write_buffer[write_index] = convert_to_char(encrypted_val) as u8;
            write_index += 1;
            i = 1; // Skip the first character as it's already used
            dangling_pt_char = None;
        } else {
            dangling_pt_char = Some(pt_char);
        }
    }
    /*-----------HANDLE DANGLING CHARACTER-----------*/

    /*-----------ENCRYPT TCP BUFFER CONTENT-----------*/
    while i < data.len() {
        if i + 1 < data.len() && data[i] as char != term_sig {
            let pt_char = data[i] as char;
            let key_char = data[i + 1] as char;
            let pt_val = convert_to_num(pt_char);
            let key_val = convert_to_num(key_char);
            let encrypted_val = (pt_val + key_val) % 27;
            write_buffer[write_index] = convert_to_char(encrypted_val) as u8;
            write_index += 1;
            i += 2;
        } else {
            // Handle dangling character or termination character
            if i + 1 >= data.len() && data[i] as char != term_sig {
                dangling_pt_char = Some(data[i] as char);
            }
            break;
        }
    }
    /*-----------ENCRYPT TCP BUFFER CONTENT-----------*/

    // Ensure the write_buffer is only filled up to write_index
    for idx in write_index..write_buffer.len() {
        write_buffer[idx] = 0;
    }

    (dangling_pt_char, write_index)
}

pub fn handle_dec_client(mut stream: TcpStream, shake_sig: char, term_sig: char) {
    /*-----------INITIALIZE-----------*/
    let mut read_buffer;
    let mut write_buffer = [0u8; CHUNK_SIZE];
    let mut write_index: usize;
    let mut dangling_ct_char: Option<char> = None;
    /*-----------INITIALIZE-----------*/

    /*-----------HANDSHAKE-----------*/
    server_handshake(&mut stream, shake_sig).expect("Handshake failed");
    /*-----------HANDSHAKE-----------*/

    loop {
        /*-----------READ TCP BUFFER-----------*/
        read_buffer = [0u8; CHUNK_SIZE];
        let read_size = match stream.read(&mut read_buffer) {
            Ok(0) => break, // Connection closed by client
            Ok(size) => size,
            Err(_) => {
                println!("Failed to read from client");
                break;
            },
        };
        /*-----------READ TCP BUFFER-----------*/

        
        (dangling_ct_char, write_index) = decrypt_data(&read_buffer[..read_size], &mut write_buffer, dangling_ct_char, term_sig);
        

        if let Err(_) = stream.write_all(&write_buffer[..write_index]) {
            println!("Failed to write to client");
            break;
        }

        if read_buffer[..read_size].contains(&(term_sig as u8)) {
            let _ = stream.write_all(term_sig.to_string().as_bytes());
            break;
        }
    }


    println!("Client disconnected");
}

pub fn handle_enc_client(mut stream: TcpStream, shake_sig: char, term_sig: char) {
    /*-----------INITIALIZE-----------*/
    let mut read_buffer;
    let mut write_buffer = [0u8; CHUNK_SIZE];
    let mut write_index: usize;
    let mut dangling_pt_char: Option<char> = None;
    /*-----------INITIALIZE-----------*/

    /*-----------HANDSHAKE-----------*/
    server_handshake(&mut stream, shake_sig).expect("Handshake failed");
    /*-----------HANDSHAKE-----------*/

    loop {
        /*-----------READ TCP BUFFER-----------*/
        read_buffer = [0u8; CHUNK_SIZE];
        let read_size = match stream.read(&mut read_buffer) {
            Ok(0) => break, // Connection closed by client
            Ok(size) => size,
            Err(_) => {
                println!("Failed to read from client");
                break;
            },
        };
        /*-----------READ TCP BUFFER-----------*/

        /*-----------ENCRYPT DATA-----------*/
        (dangling_pt_char, write_index) = encrypt_data(&read_buffer[..read_size], &mut write_buffer, dangling_pt_char, term_sig);
        /*-----------ENCRYPT DATA-----------*/

        /*-----------WRITE TO CLIENT-----------*/
        if let Err(_) = stream.write_all(&write_buffer[..write_index]) {
            println!("Failed to write to client");
            break;
        }
        /*-----------WRITE TO CLIENT-----------*/

        /*-----------SEND BACK TERMINATION SIGNAL-----------*/
        if read_buffer[..read_size].contains(&(term_sig as u8)) {
            let _ = stream.write_all(term_sig.to_string().as_bytes());
            break;
        }
        /*-----------SEND BACK TERMINATION SIGNAL-----------*/
    }


    println!("Client disconnected");
}