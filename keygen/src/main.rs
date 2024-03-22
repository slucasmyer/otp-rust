/**
 * Author:  Sullivan Lucas Myer
 * -----------------------------------------
 * Generates key for one-time pad encryption.
 * Consists of a string of random capital letters
 * and spaces, with a newline character at the end.
 * -----------------------------------------
 */
use rand::Rng;
use std::env::args;

fn main() {
    let args: Vec<String> = args().collect();
    let length: usize = args[1].parse().unwrap_or_else(|_| panic!("Invalid length"));
    let mut rng = rand::thread_rng();
    let key: String = (0..length)
        .map(|_| {
            if rng.gen_range(0..27) == 26 {
                ' '
            } else {
                ((rng.gen_range(0..26) + 65) as u8) as char
            }
        })
        .collect();
    println!("{}", key);
}