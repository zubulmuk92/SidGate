//! Sonde manuelle du backend de capture.
//!
//! `cargo run -p sidgate-capture --example probe --release`
//!
//! Mesure la cadence réelle et la part de cycles sans nouvelle image. Sur un
//! bureau immobile, `idle` doit approcher 100 %.

#[cfg(windows)]
fn main() {
    use sidgate_capture::{FrameSource, FrameStatus};
    use std::time::{Duration, Instant};

    let mut capturer = match sidgate_capture::Capturer::new(0) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("capture indisponible: {e}");
            std::process::exit(1);
        }
    };

    let desktop = capturer.desktop();
    println!("sortie {} : {}x{}", desktop.output_index, desktop.width, desktop.height);

    let (mut ready, mut idle, mut accumulated_total) = (0u64, 0u64, 0u64);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        match capturer.acquire(Duration::from_millis(100)) {
            Ok(FrameStatus::Ready { accumulated }) => {
                ready += 1;
                accumulated_total += u64::from(accumulated);
            }
            Ok(FrameStatus::Idle) => idle += 1,
            Err(e) => {
                eprintln!("acquisition interrompue: {e}");
                break;
            }
        }
    }

    let seconds = start.elapsed().as_secs_f64();
    println!("images   : {ready} ({:.1} i/s)", ready as f64 / seconds);
    println!("cycles à vide : {idle}");
    println!("présentations cumulées : {accumulated_total}");
    println!("pointeur : {:?}", capturer.pointer());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sonde disponible uniquement sous Windows");
}
