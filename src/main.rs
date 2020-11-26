use std::{io::BufReader, path::PathBuf, io::Read};

use clap::{Arg, App, crate_version};
use data_encoding::HEXLOWER;
use ring::digest::Context;

#[derive(Debug)]
enum PathError {
    PathNotFound(String),
    NotAFile(String)
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Some Path error")
    }
}
impl std::error::Error for PathError {}

fn main() -> Result<(), anyhow::Error> {
    let matches = App::new("compare_hash")
        .version(crate_version!())
        .arg(Arg::with_name("hash")
            .short("h")
            .long("hash")
            .value_name("HASH")
            .help("Hash string that will be used for comparison.")
            .multiple(false)
            .takes_value(true)
        )
        .arg(Arg::with_name("file")
            .value_name("FILE")
            .help("File that will be hashed for comparison.")
            .multiple(false)
            .required_unless("hash")
            .index(2)
        )
        .arg(Arg::with_name("input")
            .value_name("INPUT")
            .help("Hash that will be compared against.")
            .multiple(false)
            .required(true)
            .index(1)
        )
        .get_matches();

    let second_hash = matches.value_of("input").unwrap();

    if matches.is_present("file") {
        let user_input = matches.value_of("file").unwrap();
        let path = PathBuf::from(user_input);

        if !path.exists() {
            return Err(anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::NotFound, "Path does not exist.")));
        }

        if !path.is_file() {
            return Err(anyhow::Error::new(PathError::NotAFile("path does not point to a file".to_string())));
        }

        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut digest = Context::new(&ring::digest::SHA256);
        let mut buffer = vec![0; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }

        let encoded_hash= HEXLOWER.encode(digest.finish().as_ref()); 
        let is_equal = compare_hash(&encoded_hash, second_hash);
        dbg!(encoded_hash);
        dbg!(is_equal);
    } else if matches.is_present("hash") {
        let first_hash = matches.value_of("hash").unwrap();
        let is_equal = compare_hash(first_hash, second_hash);
    } else {
        unreachable!();
    };

    Ok(())

}

fn compare_hash(first_hash: &str, second_hash: &str) -> bool {
    first_hash == second_hash
}
