use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "../src/main.rs"]
mod vanaddy;

use vanaddy::chains::{bitcoin::Bitcoin, evm::Evm, monero::Monero, solana::Solana, ton::Ton, Chain};

fn bench_solana(c: &mut Criterion) {
    c.bench_function("solana_generate", |b| {
        b.iter(|| black_box(Solana::generate()))
    });
}

fn bench_evm(c: &mut Criterion) {
    c.bench_function("evm_generate", |b| {
        b.iter(|| black_box(Evm::generate()))
    });
}

fn bench_bitcoin(c: &mut Criterion) {
    c.bench_function("bitcoin_generate", |b| {
        b.iter(|| black_box(Bitcoin::generate()))
    });
}

fn bench_ton(c: &mut Criterion) {
    // TON is intentionally slow (~50-100ms/wallet due to PBKDF2 + ~1/256 filter).
    // Use a smaller sample_size to keep bench time reasonable.
    let mut group = c.benchmark_group("ton");
    group.sample_size(10);
    group.bench_function("ton_generate", |b| {
        b.iter(|| black_box(Ton::generate()))
    });
    group.finish();
}

fn bench_monero(c: &mut Criterion) {
    c.bench_function("monero_generate", |b| {
        b.iter(|| black_box(Monero::generate()))
    });
}

criterion_group!(benches, bench_solana, bench_evm, bench_bitcoin, bench_ton, bench_monero);
criterion_main!(benches);
