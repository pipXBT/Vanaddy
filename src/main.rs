use csv::WriterBuilder;
use solana_sdk::signature::{Keypair, Signer};
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

fn main() -> io::Result<()> {
    display_banner();
    let vanity_string = read_vanity_string()?;
    let case_sensitive = read_case_sensitivity()?;
    let max_threads = read_thread_count()?;
    let csv_file_path = "vanity_wallets.csv".to_string();

    prepare_csv_file(&csv_file_path)?;

    let found_flag = Arc::new(AtomicBool::new(false));
    let wallet_count = Arc::new(Mutex::new(0));

    let (tx, rx) = mpsc::channel();
    let handles = spawn_threads(
        max_threads,
        vanity_string,
        case_sensitive,
        found_flag.clone(),
        wallet_count.clone(),
        tx,
    );

    let writer_handle = start_csv_writer_thread(rx, csv_file_path);

    // Periodically print the count of generated wallets
    let counter_handle = {
        let wallet_count = wallet_count.clone();
        let found_flag = found_flag.clone();
        thread::spawn(move || {
            while !found_flag.load(Ordering::SeqCst) {
                print!("\rWallets generated: {}", wallet_count.lock().unwrap());
                io::stdout().flush().unwrap();
                thread::sleep(Duration::from_millis(25));
            }
        })
    };

    for handle in handles {
        let _ = handle.join();
    }

    let _ = writer_handle.join();
    let _ = counter_handle.join(); // Ensure the counter thread is also joined
    report_completion(&found_flag, &wallet_count, Instant::now());

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
    Ok(vanity_string.trim().to_owned())
}

fn read_case_sensitivity() -> io::Result<bool> {
    println!("Should the search be case-sensitive? (yes/no): ");
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

fn read_thread_count() -> io::Result<usize> {
    println!("Enter the number of threads to use: ");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    input
        .trim()
        .parse::<usize>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn prepare_csv_file(path: &str) -> io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "Public Key,Note")?;
    Ok(())
}

fn spawn_threads(
    max_threads: usize,
    vanity_string: String,
    case_sensitive: bool,
    found_flag: Arc<AtomicBool>,
    wallet_count: Arc<Mutex<u64>>,
    tx: mpsc::Sender<String>,
) -> Vec<thread::JoinHandle<()>> {
    (0..max_threads)
        .map(|_| {
            let vanity_string = vanity_string.clone();
            let found_flag = Arc::clone(&found_flag);
            let wallet_count = Arc::clone(&wallet_count);
            let tx = tx.clone();

            thread::spawn(move || {
                while !found_flag.load(Ordering::Relaxed) {
                    let keypair = Keypair::new();
                    let public_key = keypair.pubkey().to_string();

                    if check_vanity_string(&public_key, &vanity_string, case_sensitive) {
                        tx.send(public_key).unwrap();
                        found_flag.store(true, Ordering::Relaxed);
                        break;
                    }

                    let mut count = wallet_count.lock().unwrap();
                    *count += 1;
                }
            })
        })
        .collect()
}

fn start_csv_writer_thread(
    rx: mpsc::Receiver<String>,
    csv_file_path: String,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut wtr = WriterBuilder::new().from_path(&csv_file_path).unwrap();
        while let Ok(public_key) = rx.recv() {
            wtr.write_record(&[&public_key, "Seed Phrase Not Stored"])
                .unwrap();
            wtr.flush().unwrap();
        }
    })
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

fn report_completion(
    found_flag: &Arc<AtomicBool>,
    wallet_count: &Arc<Mutex<u64>>,
    start_time: Instant,
) {
    if found_flag.load(Ordering::Relaxed) {
        println!("Vanity address found!");
    } else {
        println!("Vanity address not found.");
    }
    let count = wallet_count.lock().unwrap();
    println!("Wallets generated: {}", count);
    println!("Elapsed time: {:?}", start_time.elapsed());
}
