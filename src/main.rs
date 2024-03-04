use csv::WriterBuilder;
use solana_sdk::signature::{Keypair, Signer};
use std::{
    fs::File,
    io::{self, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Instant,
};

fn main() -> io::Result<()> {
    display_banner();
    let vanity_string = read_vanity_string()?;
    let case_sensitive = read_case_sensitivity()?;
    let max_threads = read_thread_count()?;
    let csv_file_path = "vanity_wallets.csv".to_string(); // Example path
    prepare_csv_file(&csv_file_path)?;

    let found_flag = Arc::new(AtomicBool::new(false));
    let wallet_count = Arc::new(Mutex::new(0u64));
    let start_time = Instant::now();
    let handles = spawn_threads(
        max_threads,
        vanity_string,
        case_sensitive,
        csv_file_path,
        Arc::clone(&found_flag),
        Arc::clone(&wallet_count),
    );

    for handle in handles {
        handle.join().unwrap();
    }
    report_completion(start_time, Arc::clone(&wallet_count));

    Ok(())
}

fn display_banner() {
    println!("██╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗");
    println!("██║   ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝");
    println!("██║   ██║███████║██╔██╗ ██║███████║██║  ██║██║  ██║ ╚████╔╝ ");
    println!("╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══██║██║  ██║██║  ██║  ╚██╔╝  ");
    println!(" ╚████╔╝ ██║  ██║██║ ╚████║██║  ██║██████╔╝██████╔╝   ██║   ");
    println!("  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═════╝    ╚═╝   ");
    println!("==========================================================\n");
}

fn read_vanity_string() -> io::Result<String> {
    println!("Enter a vanity string (1-9 characters): ");
    let mut vanity_string = String::new();
    io::stdin().read_line(&mut vanity_string)?;
    Ok(vanity_string.trim().to_string())
}

fn read_case_sensitivity() -> io::Result<bool> {
    println!("Should the search be case-sensitive? (yes/no): ");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("yes"))
}

fn read_thread_count() -> io::Result<usize> {
    println!("Enter the number of threads to use: ");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().parse::<usize>().unwrap_or(1)) // Default to 1 thread if parsing fails
}

fn prepare_csv_file(path: &str) -> io::Result<()> {
    if !Path::new(path).exists() {
        let mut file = File::create(path)?;
        writeln!(file, "Public Key,Note")?;
    }
    Ok(())
}

fn spawn_threads(
    max_threads: usize,
    vanity_string: String,
    case_sensitive: bool,
    csv_file_path: String,
    found_flag: Arc<AtomicBool>,
    wallet_count: Arc<Mutex<u64>>,
) -> Vec<thread::JoinHandle<()>> {
    (0..max_threads)
        .map(|_| {
            let vanity_string = vanity_string.clone();
            let csv_file_path = csv_file_path.clone();
            let found_flag = Arc::clone(&found_flag);
            let wallet_count = Arc::clone(&wallet_count);

            thread::spawn(move || {
                let mut wtr = WriterBuilder::new().from_path(&csv_file_path).unwrap();
                while !found_flag.load(Ordering::SeqCst) {
                    let keypair = Keypair::new();
                    let public_key = keypair.pubkey().to_string();
                    if check_vanity_string(&public_key, &vanity_string, case_sensitive) {
                        wtr.write_record(&[&public_key, "Seed Phrase Not Stored"])
                            .unwrap();
                        wtr.flush().unwrap();
                        found_flag.store(true, Ordering::SeqCst);
                        println!("Found matching public key: {}", public_key);
                        break;
                    }
                    let mut count = wallet_count.lock().unwrap();
                    *count += 1;
                }
            })
        })
        .collect()
}

fn check_vanity_string(public_key: &str, vanity_string: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        public_key.starts_with(vanity_string)
    } else {
        public_key
            .to_lowercase()
            .starts_with(&vanity_string.to_lowercase())
    }
}

fn report_completion(start_time: Instant, wallet_count: Arc<Mutex<u64>>) {
    let duration = start_time.elapsed();
    let count = wallet_count.lock().unwrap();
    println!("Completed in {:?}. Wallets generated: {}", duration, count);
}
