use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "../src/main.rs"]
mod vanaddy;

use vanaddy::chains::{evm::Evm, solana::Solana, Chain};

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

criterion_group!(benches, bench_solana, bench_evm);
criterion_main!(benches);
