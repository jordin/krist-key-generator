use crypto_hash::{hex_digest, Algorithm};
use std::env;

#[inline]
fn double_sha256(input: String) -> String {
    sha256(sha256(input))
}

#[inline]
fn sha256(input: String) -> String {
    hex_digest(Algorithm::SHA256, input.as_bytes())
}

const HEX_TO_BASE36_TABLE: [char; 256] = [
    '0', '0', '0', '0', '0', '0', '0', '1', '1', '1', '1', '1', '1', '1', '2', '2', '2', '2', '2',
    '2', '2', '3', '3', '3', '3', '3', '3', '3', '4', '4', '4', '4', '4', '4', '4', '5', '5', '5',
    '5', '5', '5', '5', '6', '6', '6', '6', '6', '6', '6', '7', '7', '7', '7', '7', '7', '7', '8',
    '8', '8', '8', '8', '8', '8', '9', '9', '9', '9', '9', '9', '9', 'a', 'a', 'a', 'a', 'a', 'a',
    'a', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'd', 'd', 'd', 'd',
    'd', 'd', 'd', 'e', 'e', 'e', 'e', 'e', 'e', 'e', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'g', 'g',
    'g', 'g', 'g', 'g', 'g', 'h', 'h', 'h', 'h', 'h', 'h', 'h', 'i', 'i', 'i', 'i', 'i', 'i', 'i',
    'j', 'j', 'j', 'j', 'j', 'j', 'j', 'k', 'k', 'k', 'k', 'k', 'k', 'k', 'l', 'l', 'l', 'l', 'l',
    'l', 'l', 'm', 'm', 'm', 'm', 'm', 'm', 'm', 'n', 'n', 'n', 'n', 'n', 'n', 'n', 'o', 'o', 'o',
    'o', 'o', 'o', 'o', 'p', 'p', 'p', 'p', 'p', 'p', 'p', 'q', 'q', 'q', 'q', 'q', 'q', 'q', 'r',
    'r', 'r', 'r', 'r', 'r', 'r', 's', 's', 's', 's', 's', 's', 's', 't', 't', 't', 't', 't', 't',
    't', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'v', 'v', 'v', 'v', 'v', 'v', 'v', 'w', 'w', 'w', 'w',
    'w', 'w', 'w', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'y', 'y', 'y', 'y', 'y', 'y', 'y', 'z', 'z',
    'z', 'z', 'z', 'z', 'z', 'e', 'e', 'e', 'e',
];

fn make_address(pkey: String) -> String {
    let mut address: Vec<char> = vec!['k'];
    let mut chars: Vec<char> = vec![' '; 9];

    let mut hash = double_sha256(pkey);

    for i in 0..9 {
        let num = &hash[0..2];
        let hex = usize::from_str_radix(num, 16).unwrap();
        chars[i] = HEX_TO_BASE36_TABLE[hex];
        hash = double_sha256(hash);
    }

    let mut used: Vec<bool> = vec![false; 9];

    let mut i = 0;

    while i < 9 {
        let str_index = 2 * i;
        let num = &hash[str_index..str_index + 2];
        let index = usize::from_str_radix(num, 16).unwrap() % 9;

        if used[index] {
            hash = sha256(hash);
        } else {
            used[index] = true;
            i += 1;

            address.push(chars[index]);
        }
    }

    address.into_iter().collect()
}

fn main() {
    let args: Vec<String> = env::args().into_iter().collect();

    if let Some(input) = args.get(1) {
        let input_num = input.parse::<u64>().expect("Please enter a valid number.");
        let hex_string = format!("{:016x}", input_num);
        println!("Password: {}", hex_string);

        let private_key = sha256(String::from("KRISTWALLET") + &hex_string) + "-000";

        println!("Private Key: {}", private_key);

        let address = make_address(private_key);

        println!("Address: {}", address);
    } else {
        eprintln!("Enter in the seed number.");
    }
}
