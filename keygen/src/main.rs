use rand::Rng; // Add `rand` crate to `Cargo.toml`

fn main() {
    let args: Vec<String> = std::env::args().collect();
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

