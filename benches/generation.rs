use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "../src/main.rs"]
mod vanaddy;

fn bench_solana(c: &mut Criterion) {
    c.bench_function("solana_generate", |b| {
        b.iter(|| black_box(vanaddy::generate_solana_raw()))
    });
}

fn bench_evm(c: &mut Criterion) {
    c.bench_function("evm_generate", |b| {
        b.iter(|| black_box(vanaddy::generate_evm_raw()))
    });
}

criterion_group!(benches, bench_solana, bench_evm);
criterion_main!(benches);
