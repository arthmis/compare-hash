use std::{io::BufReader, io::Read, path::PathBuf};

use clap::{crate_version, App, Arg};
use data_encoding::HEXLOWER;
use ring::digest::Context;

mod file_lock;

use file_lock::Lock;
#[derive(Debug)]
enum PathError {
    PathNotFound(String),
    NotAFile(String),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotFound(message) => write!(f, "{}", message),
            Self::NotAFile(message) => write!(f, "{}", message),
        }
    }
}
impl std::error::Error for PathError {}

fn main() -> Result<(), anyhow::Error> {
    let matches = App::new("compare_hash")
        .version(crate_version!())
        .arg(
            Arg::with_name("hash")
                .short("h")
                .long("hash")
                .value_name("HASH")
                .help("Hash string that will be used for comparison.")
                .multiple(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("File that will be hashed for comparison.")
                .multiple(false)
                .takes_value(true)
                .conflicts_with("hash"),
        )
        .arg(
            Arg::with_name("input")
                .value_name("INPUT")
                .help("Hash that will be compared against.")
                .multiple(false)
                .required(true),
        )
        .usage("compare_hash [OPTIONS] <INPUT>\n    One of the [OPTIONS] is required")
        .get_matches();

    let second_hash = matches.value_of("input").unwrap();

    if matches.is_present("file") {
        let user_input = matches.value_of("file").unwrap();
        let path = PathBuf::from(user_input);

        if !path.exists() {
            return Err(anyhow::Error::from(PathError::PathNotFound(format!(
                "Path does not exist: {:#?}",
                path
            ))));
        }

        if !path.is_file() {
            return Err(anyhow::Error::new(PathError::NotAFile(format!(
                "Path does not point to a file: {:#?}",
                path
            ))));
        }

        let lock = Lock::new(&path, false, false, false)?;
        let mut reader = BufReader::new(lock.file());
        let mut digest = Context::new(&ring::digest::SHA256);
        let mut buffer = vec![0; 8192];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }

        let encoded_hash = HEXLOWER.encode(digest.finish().as_ref());
        let is_equal = compare_hash(&encoded_hash, second_hash);
        if is_equal {
            println!(
                "The digest of {:#?} is equal to the hash input {}\n",
                &path, second_hash
            );
        } else {
            println!("The digest of {:#?} is not equal to the hash input {}\n. The digest of the file was {}\n", &path, second_hash, encoded_hash);
        }
    } else if matches.is_present("hash") {
        let first_hash = matches.value_of("hash").unwrap();
        let is_equal = compare_hash(first_hash, second_hash);
        if is_equal {
            println!(
                "The hashes are equal.",
            );
        } else {
            println!("The hashes are not equal");
        }
    } else {
        unreachable!();
    };

    Ok(())
}

fn compare_hash(first_hash: &str, second_hash: &str) -> bool {
    first_hash == second_hash
}
