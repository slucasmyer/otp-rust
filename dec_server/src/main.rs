/*-----------USE STATEMENTS-----------*/
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::env;
/*-----------USE STATEMENTS-----------*/

/*-----------CONSTANT DEFINITIONS-----------*/
const CHUNK_SIZE: usize = 1000;
const HANDSHAKE_SIGNAL: char = '@';
const TERMINATION_SIGNAL: char = '@';
/*-----------CONSTANT DEFINITIONS-----------*/

/*-----------UTILITY FUNCTIONS-----------*/
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

fn perform_handshake(stream: &mut TcpStream) -> io::Result<()> {
    let mut handshake_buffer = [0; 1];
    stream.read_exact(&mut handshake_buffer)?;

    if handshake_buffer[0] as char != HANDSHAKE_SIGNAL {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Handshake failed"));
    }

    stream.write_all(&(HANDSHAKE_SIGNAL as u8).to_be_bytes())?;
    Ok(())
}

fn decrypt_data(data: &[u8], write_buffer: &mut [u8], mut dangling_pt_char: Option<char>) -> (Option<char>, usize) {
    let mut write_index = 0;
    let mut i = 0;

    /*-----------HANDLE DANGLING CHARACTER-----------*/
    if let Some(pt_char) = dangling_pt_char {
        if !data.is_empty() {
            let key_char = data[0] as char;
            let pt_val = convert_to_num(pt_char);
            let key_val = convert_to_num(key_char);
            // let encrypted_val = (pt_val + key_val) % 27;
            let decrypted_val = (pt_val - key_val + 27) % 27;
            write_buffer[write_index] = convert_to_char(decrypted_val) as u8;
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
        if i + 1 < data.len() && data[i] as char != TERMINATION_SIGNAL {
            let pt_char = data[i] as char;
            let key_char = data[i + 1] as char;
            let pt_val = convert_to_num(pt_char);
            let key_val = convert_to_num(key_char);
            if pt_val >= 0 && key_val >= 0 { // This check is implicit in your use of convert_to_num
                // let encrypted_val = (pt_val + key_val) % 27;
                let decrypted_val = (pt_val - key_val + 27) % 27;
                write_buffer[write_index] = convert_to_char(decrypted_val) as u8;
                write_index += 1;
            }
            i += 2;
        } else {
            // Handle dangling character or termination character
            if i + 1 >= data.len() && data[i] as char != TERMINATION_SIGNAL {
                dangling_pt_char = Some(data[i] as char);
            }
            break;
        }
    }
    /*-----------ENCRYPT TCP BUFFER CONTENT-----------*/

    // Ensure the write_buffer is only filled up to write_index
    for idx in write_index..write_buffer.len() {
        write_buffer[idx] = 0; // You might choose to leave as is, based on how it's used downstream
    }

    (dangling_pt_char, write_index)
}

// fn decrypt_data(data: &[u8], dangling_ct_char: Option<char>) -> (Vec<u8>, Option<char>) {
//     let mut decrypted_data = Vec::new();
//     let mut i = 0;
//     let mut new_dangling_ct_char = None;

//     if let Some(ct_char) = dangling_ct_char {
//         if !data.is_empty() {
//             let key_char = data[0] as char;
//             let ct_val = convert_to_num(ct_char);
//             let key_val = convert_to_num(key_char);
//             if ct_val >= 0 && key_val >= 0 {
//                 let decrypted_val = (ct_val - key_val + 27) % 27;
//                 decrypted_data.push(convert_to_char(decrypted_val) as u8);
//             }
//             i += 1;
//         } else {
//             new_dangling_ct_char = Some(ct_char);
//         }
//     }

//     while i < data.len() {
//         if data[i] as char == TERMINATION_SIGNAL {
//             break;
//         }
        
//         if i + 1 < data.len() {
//             let ct_char = data[i] as char;
//             let key_char = data[i + 1] as char;
//             let ct_val = convert_to_num(ct_char);
//             let key_val = convert_to_num(key_char);
//             if ct_val >= 0 && key_val >= 0 {
//                 let decrypted_val = (ct_val - key_val + 27) % 27;
//                 decrypted_data.push(convert_to_char(decrypted_val) as u8);
//             }
//             i += 2;
//         } else {
//             new_dangling_ct_char = Some(data[i] as char);
//             break;
//         }
//     }

//     (decrypted_data, new_dangling_ct_char)
// }

// fn handle_client(mut stream: TcpStream) {
//     let mut buffer = [0u8; CHUNK_SIZE];
//     if let Err(_) = stream.read_exact(&mut buffer[..1]) {
//         return;
//     }

//     if buffer[0] as char != HANDSHAKE_SIGNAL {
//         return;
//     }

//     stream.write_all(&[HANDSHAKE_SIGNAL as u8]).unwrap();

//     let mut dangling_ct_char: Option<char> = None;
//     while let Ok(size) = stream.read(&mut buffer) {
//         if size == 0 {
//             break; // Connection closed
//         }

//         let (decrypted_data, new_dangling_ct_char) = decrypt_data(&buffer[..size], dangling_ct_char);
//         dangling_ct_char = new_dangling_ct_char;

//         if stream.write_all(&decrypted_data).is_err() {
//             break; // Handle write error or disconnect
//         }

//         if size < CHUNK_SIZE {
//             break; // Last chunk processed
//         }
//     }

//     println!("Client disconnected");
// }

/*-----------CHILD-----------*/
fn handle_client(mut stream: TcpStream) {
    /*-----------INITIALIZE CHILD-----------*/
    let mut read_buffer;
    let mut write_buffer = [0u8; CHUNK_SIZE];
    let mut write_index: usize;
    let mut dangling_pt_char: Option<char> = None;
    /*-----------INITIALIZE CHILD-----------*/

    /*-----------HANDSHAKE-----------*/
    perform_handshake(&mut stream).expect("Handshake failed");
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

        
        (dangling_pt_char, write_index) = decrypt_data(&read_buffer[..read_size], &mut write_buffer, dangling_pt_char);
        

        if let Err(_) = stream.write_all(&write_buffer[..write_index]) {
            println!("Failed to write to client");
            break;
        }

        if read_buffer[..read_size].contains(&(TERMINATION_SIGNAL as u8)) {
            let _ = stream.write_all(TERMINATION_SIGNAL.to_string().as_bytes());
            break;
        }
    }


    println!("Client disconnected");
}
/*-----------CHILD-----------*/

/*-----------UTILITY FUNCTIONS-----------*/

/*-----------MAIN-----------*/
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
/*-----------MAIN-----------*/