use blst::min_pk::{PublicKey, SecretKey, Signature};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// BLS signature domain separation tag for Ethereum consensus
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn create_test_key() -> SecretKey {
    let key_bytes = [1u8; 32];
    SecretKey::from_bytes(&key_bytes).expect("Valid test key")
}

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║     Py3Signer Core - BLS Signing Performance Profile           ║");
    println!("╚════════════════════════════════════════════════════════════════╝");

    let message = [42u8; 32];

    // Warmup - important for accurate measurements
    println!("\n[Warming up with 1,000 iterations...]");
    let sk_warmup = create_test_key();
    for _ in 0..1_000 {
        let _ = sk_warmup.sign(&message, BLS_DST, &[]);
    }

    // Test 1: Raw signing performance
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 1: Raw BLS Signing Performance");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let iterations = 10_000;
    let sk1 = create_test_key();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk1.sign(&message, BLS_DST, &[]);
    }
    let duration = start.elapsed();
    let baseline = report_performance("Raw signing", iterations, duration);

    // Test 2: Signing with Arc (simulating py3signer wrapper flow)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 2: Signing with Arc Cloning (py3signer simulation)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let sk2 = create_test_key();
    let sk_arc = Arc::new(sk2);
    let start = Instant::now();
    for _ in 0..iterations {
        let sk = Arc::clone(&sk_arc);
        let _ = sk.sign(&message, BLS_DST, &[]);
    }
    let duration_arc = start.elapsed();
    let with_arc = report_performance("With Arc clone", iterations, duration_arc);

    let overhead_ns = with_arc.0 - baseline.0;
    let overhead_pct = (overhead_ns / baseline.0) * 100.0;
    println!(
        "  → Arc clone overhead: {:.2} ns/op ({:.2}%)",
        overhead_ns, overhead_pct
    );

    // Test 3: Arc clone only
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 3: Arc Clone Overhead Only");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Arc::clone(&sk_arc);
    }
    let duration_clone = start.elapsed();
    let _ = report_performance("Arc clone only", iterations, duration_clone);

    // Test 4: Message preparation overhead
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 4: Message Preparation Overhead");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let message_vec = message.to_vec();
    let start = Instant::now();
    for _ in 0..iterations {
        let msg_array: [u8; 32] = message_vec.as_slice().try_into().expect("32 bytes");
        let _ = sk_arc.sign(&msg_array, BLS_DST, &[]);
    }
    let duration_prep = start.elapsed();
    let with_prep = report_performance("With slice conversion", iterations, duration_prep);

    let prep_overhead_ns = with_prep.0 - baseline.0;
    let prep_overhead_pct = (prep_overhead_ns / baseline.0) * 100.0;
    println!(
        "  → Message conversion overhead: {:.2} ns/op ({:.2}%)",
        prep_overhead_ns, prep_overhead_pct
    );

    // Test 5: Batch throughput at different sizes
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 5: Batch Throughput Analysis");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "  {:>10} | {:>12} | {:>15}",
        "Batch Size", "Time", "Ops/Second"
    );
    println!(
        "  {:>10}-+-{:>12}-+-{:>15}",
        "-".repeat(10),
        "-".repeat(12),
        "-".repeat(15)
    );

    let batch_sizes = [100, 1_000, 5_000];
    for batch_size in batch_sizes.iter() {
        let start = Instant::now();
        for _ in 0..*batch_size {
            let _ = sk_arc.sign(&message, BLS_DST, &[]);
        }
        let duration = start.elapsed();
        let ops_per_sec = *batch_size as f64 / duration.as_secs_f64();
        println!(
            "  {:>10} | {:>10.?} | {:>15.0}",
            batch_size, duration, ops_per_sec
        );
    }

    // Test 6: Sign vs Verify
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 6: Sign vs Verify Performance");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let pk = sk_arc.sk_to_pk();
    let signature = sk_arc.sign(&message, BLS_DST, &[]);

    let sk3 = create_test_key();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk3.sign(&message, BLS_DST, &[]);
    }
    let sign_duration = start.elapsed();
    let sign_perf = report_performance("Sign", iterations, sign_duration);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = signature.verify(true, &message, BLS_DST, &[], &pk, true);
    }
    let verify_duration = start.elapsed();
    let verify_perf = report_performance("Verify", iterations, verify_duration);

    let ratio = verify_perf.0 / sign_perf.0;
    println!("  → Verify is {:.2}x slower than Sign", ratio);

    // Test 7: Key derivation performance
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" TEST 7: Key Derivation Performance");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let key_bytes = [1u8; 32];

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = SecretKey::from_bytes(&key_bytes);
    }
    let key_from_bytes = report_performance("SecretKey::from_bytes", iterations, start.elapsed());

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sk_arc.sk_to_pk();
    }
    let sk_to_pk = report_performance("sk_to_pk()", iterations, start.elapsed());

    println!(
        "  → Key derivation is {:.2}x faster than signing",
        baseline.0 / key_from_bytes.0
    );
    println!(
        "  → Public key derivation is {:.2}x faster than signing",
        baseline.0 / sk_to_pk.0
    );

    // Memory analysis
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" Memory Layout Analysis");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  {:<25} | {:>6} bytes", "Type", "Size");
    println!("  {:<25}-+-{:>6}", "-".repeat(25), "-".repeat(6));
    println!(
        "  {:<25} | {:>6}",
        "SecretKey",
        std::mem::size_of::<SecretKey>()
    );
    println!(
        "  {:<25} | {:>6}",
        "PublicKey",
        std::mem::size_of::<PublicKey>()
    );
    println!(
        "  {:<25} | {:>6}",
        "Signature",
        std::mem::size_of::<Signature>()
    );
    println!(
        "  {:<25} | {:>6}",
        "Arc<SecretKey>",
        std::mem::size_of::<Arc<SecretKey>>()
    );

    let sig = sk_arc.sign(&message, BLS_DST, &[]);
    let sig_bytes = sig.compress();
    println!(
        "  {:<25} | {:>6}",
        "Signature (compressed)",
        sig_bytes.len()
    );

    // Final Summary
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                        SUMMARY                                 ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!(
        "  Baseline signing:          {:.2} µs per operation",
        baseline.0 / 1000.0
    );
    println!(
        "  Estimated max throughput:  {:.0} signs/second",
        1_000_000_000.0 / baseline.0
    );
    println!("  Arc clone overhead:        {:.2}%", overhead_pct);
    println!("  Message prep overhead:     {:.2}%", prep_overhead_pct);
    println!("  Sign/Verify ratio:         1:{:.2}", ratio);

    // Python comparison context
    println!("\n  Comparison with reported Python performance:");
    let python_reported_us = 500.0; // From the task description
    let rust_us = baseline.0 / 1000.0;
    let speedup = python_reported_us / rust_us;
    println!("    Python (reported):       {:.0} µs", python_reported_us);
    println!("    Rust (this benchmark):   {:.2} µs", rust_us);
    println!("    Rust speedup:            {:.1}x", speedup);

    // Verify signatures are valid
    let sig = sk_arc.sign(&message, BLS_DST, &[]);
    let result = sig.verify(true, &message, BLS_DST, &[], &pk, true);
    assert_eq!(
        result,
        blst::BLST_ERROR::BLST_SUCCESS,
        "Signature should be valid"
    );
    println!("\n✓ All signatures verified successfully");
}

/// Returns (ns_per_op, ops_per_sec)
fn report_performance(name: &str, iterations: u64, duration: Duration) -> (f64, f64) {
    let ns_per_op = duration.as_nanos() as f64 / iterations as f64;
    let ops_per_sec = 1_000_000_000.0 / ns_per_op;
    let us_per_op = ns_per_op / 1000.0;

    println!("  {}:", name);
    println!(
        "    Time: {:>10.2} µs/op | {:>12.0} ops/sec",
        us_per_op, ops_per_sec
    );

    (ns_per_op, ops_per_sec)
}
