use csv;
use solana_sdk::signature::{Keypair, Signer};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Instant,
};

fn get_public_key(keypair: &Keypair) -> String {
    keypair.pubkey().to_string()
}

// Function to perform case-sensitive check
fn check_vanity_string(public_key: &str, vanity_string: &str) -> bool {
    public_key.starts_with(vanity_string)
}

fn main() -> io::Result<()> {
    println!("= = = = = = = = = = = = = = = = = = = = = = = = = =\n");
    println!("██╗   ██╗ █████╗ ███╗   ██╗██████╗ ██████╗ ██╗   ██╗");
    println!("██║   ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝");
    println!("██║   ██║███████║██╔██╗ ██║██║  ██║██║  ██║ ╚████╔╝ ");
    println!("██║   ██║██╔══██║██║╚██╗██║██║  ██║██║  ██║  ╚██╔╝  ");
    println!("╚██████╔╝██║  ██║██║ ╚████║██████╔╝██████╔╝   ██║   ");
    println!("╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═════╝    ╚═╝   \n");
    println!("= = = = = = = = = = = = = = = = = = = = = = = = = =\n");

    let vanity_string = read_vanity_string()?;
    let max_threads = read_thread_count()?; // Read thread count from user
    let csv_file_path = String::from("vanity_wallets.csv");
    let found_flag = Arc::new(AtomicBool::new(false));
    let wallet_count = Arc::new(Mutex::new(0u64));
    let start_time = Instant::now();

    if !Path::new(&csv_file_path).exists() {
        let mut wtr = csv::Writer::from_path(&csv_file_path)?;
        wtr.write_record(&["Public Key", "Note"])?;
        wtr.flush()?;
    }

    let mut handles = vec![];

    for _ in 0..max_threads {
        let vanity_clone = vanity_string.clone();
        let csv_file_clone = csv_file_path.clone();
        let found_flag_clone = Arc::clone(&found_flag);
        let wallet_count_clone = Arc::clone(&wallet_count);

        let handle = thread::spawn(move || {
            while !found_flag_clone.load(Ordering::SeqCst) {
                let keypair = Keypair::new();
                let public_key = get_public_key(&keypair);

                let count = {
                    let mut num = wallet_count_clone.lock().unwrap();
                    *num += 1;
                    *num
                };

                println!("Total wallet {}: Generated key {}", count, public_key);

                if check_vanity_string(&public_key, &vanity_clone) {
                    {
                        let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(
                            OpenOptions::new()
                                .write(true)
                                .append(true)
                                .open(&csv_file_clone)
                                .unwrap(),
                        );
                        wtr.write_record(&[&public_key, "Seed Phrase Not Stored"])
                            .unwrap();
                        wtr.flush().unwrap();
                    }
                    println!("Vanity string found in public key: {}", public_key);
                    found_flag_clone.store(true, Ordering::SeqCst);
                    break;
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let elapsed_time = start_time.elapsed();
    println!("Total time elapsed: {:.2?}", elapsed_time);

    Ok(())
}

fn read_vanity_string() -> io::Result<String> {
    let mut vanity_string = String::new();
    while vanity_string.len() < 1 || vanity_string.len() > 9 {
        print!("Enter a vanity string (1-9 characters): ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut vanity_string)?;
        vanity_string = vanity_string.trim().to_string();

        if vanity_string.len() < 1 || vanity_string.len() > 9 {
            println!("The vanity string must be between 1 and 9 characters.");
        }
    }
    Ok(vanity_string)
}

fn read_thread_count() -> io::Result<usize> {
    let mut input = String::new();
    loop {
        print!("Enter the number of threads to use: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut input)?;
        match input.trim().parse::<usize>() {
            Ok(count) if count > 0 => return Ok(count),
            _ => println!("Please enter a valid positive number for threads."),
        }
    }
}
