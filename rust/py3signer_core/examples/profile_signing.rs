#![allow(clippy::cast_precision_loss, clippy::cast_lossless)]

use blst::min_pk::SecretKey;
use std::sync::Arc;
use std::time::Instant;

const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn main() {
    println!("=== Py3Signer Rust Signing Profiling ===\n");

    let key_bytes = [1u8; 32];
    let sk_arc = Arc::new(SecretKey::from_bytes(&key_bytes).expect("Valid key"));
    let message = [42u8; 32];

    // Warmup
    for _ in 0..1000 {
        let _ = sk_arc.sign(&message, BLS_DST, &[]);
    }

    let iterations = 100_000;

    // Raw signing
    println!("--- Raw BLS Signing ---");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_arc.sign(&message, BLS_DST, &[]);
    }
    let duration = start.elapsed();
    let ns_per_op = duration.as_nanos() as f64 / iterations as f64;
    println!(
        "  Time: {:.2} µs | Ops/sec: {:.0}",
        ns_per_op / 1000.0,
        1e9 / ns_per_op
    );

    // With Arc clone (py3signer simulation)
    println!("\n--- With Arc::clone ---");
    let start = Instant::now();
    for _ in 0..iterations {
        let sk = Arc::clone(&sk_arc);
        let _ = sk.sign(&message, BLS_DST, &[]);
    }
    let duration_arc = start.elapsed();
    let ns_arc = duration_arc.as_nanos() as f64 / iterations as f64;
    println!(
        "  Time: {:.2} µs | Ops/sec: {:.0}",
        ns_arc / 1000.0,
        1e9 / ns_arc
    );
    println!(
        "  Overhead: {:.2}%",
        ((ns_arc - ns_per_op) / ns_per_op) * 100.0
    );

    // Arc clone only
    println!("\n--- Arc::clone only ---");
    let start = Instant::now();
    for _ in 0..iterations {
        let _sk = Arc::clone(&sk_arc);
    }
    let ns_clone = start.elapsed().as_nanos() as f64 / iterations as f64;
    println!(
        "  Time: {:.2} ns | Overhead: {:.2}% of signing",
        ns_clone,
        (ns_clone / ns_arc) * 100.0
    );

    // Sign vs Verify
    println!("\n--- Sign vs Verify ---");
    let pk = sk_arc.sk_to_pk();
    let sig = sk_arc.sign(&message, BLS_DST, &[]);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_arc.sign(&message, BLS_DST, &[]);
    }
    let ns_sign = start.elapsed().as_nanos() as f64 / iterations as f64;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sig.verify(true, &message, BLS_DST, &[], &pk, true);
    }
    let ns_verify = start.elapsed().as_nanos() as f64 / iterations as f64;

    println!("  Sign:   {:.2} µs", ns_sign / 1000.0);
    println!("  Verify: {:.2} µs", ns_verify / 1000.0);
    println!("  Verify is {:.2}x slower", ns_verify / ns_sign);

    // Summary
    println!("\n=== Summary ===");
    println!(
        "Baseline: {:.2} µs/sign ({:.0} signs/sec)",
        ns_per_op / 1000.0,
        1e9 / ns_per_op
    );
    println!(
        "With Arc: {:.2} µs/sign ({:.0} signs/sec)",
        ns_arc / 1000.0,
        1e9 / ns_arc
    );
}
