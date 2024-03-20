use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::env;

const CHUNK_SIZE: usize = 1000;
const HANDSHAKE_SIGNAL: char = '@';
const TERMINATION_SIGNAL: char = '@';

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("USAGE: {} port", args[0]);
        std::process::exit(1);
    }

    let port = &args[1];
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).expect("Failed to bind to port");
    println!("Server listening on port {}", port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || handle_client(stream));
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let mut buffer = [0u8; CHUNK_SIZE];
    if let Err(_) = stream.read_exact(&mut buffer[..1]) {
        return;
    }

    if buffer[0] as char != HANDSHAKE_SIGNAL {
        return;
    }

    stream.write_all(&[HANDSHAKE_SIGNAL as u8]).unwrap();

    let mut dangling_ct_char: Option<char> = None;
    while let Ok(size) = stream.read(&mut buffer) {
        if size == 0 {
            break; // Connection closed
        }

        let (decrypted_data, new_dangling_ct_char) = decrypt_data(&buffer[..size], dangling_ct_char);
        dangling_ct_char = new_dangling_ct_char;

        if stream.write_all(&decrypted_data).is_err() {
            break; // Handle write error or disconnect
        }

        if size < CHUNK_SIZE {
            break; // Last chunk processed
        }
    }

    println!("Client disconnected");
}

// Adjust `decrypt_data` as previously defined, no changes needed from the last version.

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
        _ => '?', // Indicate an error (shouldn't happen with valid encryption values)
    }
}


fn decrypt_data(data: &[u8], dangling_ct_char: Option<char>) -> (Vec<u8>, Option<char>) {
    let mut decrypted_data = Vec::new();
    let mut i = 0;
    let mut new_dangling_ct_char = None;

    if let Some(ct_char) = dangling_ct_char {
        if !data.is_empty() {
            let key_char = data[0] as char;
            let ct_val = convert_to_num(ct_char);
            let key_val = convert_to_num(key_char);
            if ct_val >= 0 && key_val >= 0 {
                let decrypted_val = (ct_val - key_val + 27) % 27;
                decrypted_data.push(convert_to_char(decrypted_val) as u8);
            }
            i += 1;
        } else {
            new_dangling_ct_char = Some(ct_char);
        }
    }

    while i < data.len() {
        if data[i] as char == TERMINATION_SIGNAL {
            break;
        }
        
        if i + 1 < data.len() {
            let ct_char = data[i] as char;
            let key_char = data[i + 1] as char;
            let ct_val = convert_to_num(ct_char);
            let key_val = convert_to_num(key_char);
            if ct_val >= 0 && key_val >= 0 {
                let decrypted_val = (ct_val - key_val + 27) % 27;
                decrypted_data.push(convert_to_char(decrypted_val) as u8);
            }
            i += 2;
        } else {
            new_dangling_ct_char = Some(data[i] as char);
            break;
        }
    }

    (decrypted_data, new_dangling_ct_char)
}
