//! Smoke test for the in-memory inspect/convert surface.
//! Usage: cargo run --example memconv_smoke -- <file> [target]
use std::io::Read;

fn main() -> fstool::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: memconv_smoke <file> [target]");
    let target = args.next();

    let mut bytes = Vec::new();
    std::fs::File::open(&path)?.read_to_end(&mut bytes)?;
    println!("input: {path} ({} bytes)", bytes.len());

    let report = fstool::memconv::probe(&bytes)?;
    println!("probe: {}", serde_json::to_string_pretty(&report).unwrap());

    let mut img = fstool::memconv::MemImage::open(bytes)?;
    println!("opened as: {}", img.kind());
    for e in img.list("/")? {
        println!("  {:>10} {:<6} {}", e.size, e.kind, e.name);
    }

    if let Some(t) = target {
        let out = img.convert(&t)?;
        println!("convert -> {t}: {} bytes", out.len());
        // Re-open the result to prove it round-trips.
        match fstool::memconv::MemImage::open(out.clone()) {
            Ok(mut r) => {
                println!("  re-opened as: {}", r.kind());
                let n = r.list("/")?.len();
                println!("  root entries: {n}");
            }
            Err(e) => println!("  (result not re-openable in-memory: {e})"),
        }
    }
    Ok(())
}
