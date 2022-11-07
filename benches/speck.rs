use criterion::{black_box, criterion_group, criterion_main, Criterion};
use speck::{Speck128_128, Speck128_192, Speck128_256, Speck64_128, Speck64_96, SpeckCipher};

fn encrypt_data<const N: usize>(cipher: &dyn SpeckCipher) {
    let mut data = [0; N];
    cipher.seal_in_place(&mut data).unwrap();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("SPECK 64/96", |b| {
	let cipher = Speck64_96::new([0, 1, 2]);
	b.iter(|| {
	    black_box(encrypt_data::<8>(&cipher));
	})
    });
    c.bench_function("SPECK 64/128", |b| {
	let cipher = Speck64_128::new([0, 1, 2, 4]);
	b.iter(|| {
	    black_box(encrypt_data::<8>(&cipher));
	})
    });
    c.bench_function("SPECK 128/128", |b| {
	let cipher = Speck128_128::new([0, 1]);
	b.iter(|| {
	    black_box(encrypt_data::<16>(&cipher));
	})
    });
    c.bench_function("SPECK 128/192", |b| {
	let cipher = Speck128_192::new([0, 1, 2]);
	b.iter(|| {
	    black_box(encrypt_data::<16>(&cipher));
	})
    });
    c.bench_function("SPECK 128/256", |b| {
	let cipher = Speck128_256::new([0, 1, 2, 4]);
	b.iter(|| {
	    black_box(encrypt_data::<16>(&cipher));
	})
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
