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

fn check_vanity_string(public_key: &str, vanity_string: &str) -> bool {
    public_key.starts_with(vanity_string)
}

fn main() -> io::Result<()> {
    println!("██╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗");
    println!("██║   ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝");
    println!("██║   ██║███████║██╔██╗ ██║███████║██║  ██║██║  ██║ ╚████╔╝ ");
    println!("╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══██║██║  ██║██║  ██║  ╚██╔╝  ");
    println!(" ╚████╔╝ ██║  ██║██║ ╚████║██║  ██║██████╔╝██████╔╝   ██║   ");
    println!("  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═════╝    ╚═╝   ");
    println!("==========================================================\n");

    let vanity_string = read_vanity_string()?;
    let max_threads = read_thread_count()?;
    let csv_file_path = String::from("wallets.csv");
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

                {
                    let mut num = wallet_count_clone.lock().unwrap();
                    *num += 1;
                    if *num % 100 == 0 {
                        println!("Checked Wallets: {}", *num);
                    }
                    // Explicitly drop the lock to release it as soon as we're done
                    drop(num);
                }

                if check_vanity_string(&public_key, &vanity_clone) {
                    {
                        let mut wtr = csv::WriterBuilder::new().has_headers(false).from_writer(
                            OpenOptions::new()
                                .write(true)
                                .append(true)
                                .open(&csv_file_clone)
                                .unwrap(),
                        );
                        wtr.write_record(&[&public_key, "Seed Phrase Not Stored"]).unwrap();
                        // Ensure the writer is flushed and dropped explicitly
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

    // Join all threads and handle potential errors
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread ended with an error: {:?}", e);
        }
    }

    let elapsed_time = start_time.elapsed();
    println!("Total time: {:.1?}", elapsed_time);

    Ok(())
}

fn read_vanity_string() -> io::Result<String> {
    let mut vanity_string = String::new();
    print!("Enter a vanity string (1-9 characters): ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut vanity_string)?;
    vanity_string = vanity_string.trim().to_string();

    while vanity_string.len() < 1 || vanity_string.len() > 9 {
        println!("The vanity string must be between 1 and 9 characters.");
        vanity_string.clear();
        io::stdin().read_line(&mut vanity_string)?;
        vanity_string = vanity_string.trim().to_string();
    }

    Ok(vanity_string)
}

fn read_thread_count() -> io::Result<usize> {
    let mut input = String::new();
    print!("Enter the number of threads to use: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    match input.trim().parse::<usize>() {
        Ok(count) if count > 0 => Ok(count),
        _ => {
            println!("Please enter a valid positive number for threads.");
            read_thread_count() // Recursively prompt until a valid input is received
        }
    }
}
