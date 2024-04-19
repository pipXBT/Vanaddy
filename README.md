# Vanaddy

Vanaddy is a Rust-based utility for generating Solana keypairs and finding an input vanity sting at the beginning of the addy.
It process concurrently to efficiently search for public keys that match a user-defined vanity string.


## Features

- **Vanity String Matching**: Searches for Solana public keys that start with a specified vanity string.
- **Case Sensitivity**: The matching process is case-sensitive, ensuring precise alignment with the user's requirements.
- **Multi-threading Support**: Utilizes multiple threads to speed up the search process, with the thread count definable by the user (approx. 1 billion addy's a day)
- **CSV Logging**: Records found public keys in a CSV file for easy access and reference.

- On an Apple silicon M1 machine 6 threads was approx 50% cpu load ,it will ask hoa many threads you want use.

## Installation

To use Vanaddy, ensure you have Rust installed on your machine. You can install Rust using [rustup](https://rustup.rs/).

After installing Rust, clone the repository and navigate to the project directory:

```
git clone https://github.com/PipXBT/vanddy
```
```
cd vanaddy
```
```
cargo build
```
```
cargo run 
```


![Screen Recording 2024-01-28 at 3 49 34 pm](https://github.com/PipXBT/vanddy/assets/84630076/e3545aa9-024b-46d7-9fb9-1507967fa0d2)
