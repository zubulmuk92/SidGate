//! Banc d'essai capture + encodage matériel.
//!
//! `cargo run -p sidgate-encode --example bench --release -- [secondes] [sortie.h264] [--synthetic]`
//!
//! Écrit un flux Annex-B lisible par VLC ou ffplay. Si le fichier est lisible,
//! c'est que la chaîne VRAM -> NV12 -> ASIC fonctionne de bout en bout.
//!
//! En mode `--synthetic`, la même texture est resoumise sans discontinuer : on
//! mesure alors le débit maximal de l'ASIC, indépendamment de ce que le bureau
//! veut bien présenter. C'est la mesure qui compte pour savoir si la machine
//! tient 60 i/s.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use sidgate_capture::{FrameSource, FrameStatus};
    use sidgate_encode::{EncodedFrame, Encoder, EncoderConfig, Submission};
    use std::io::Write;
    use std::time::{Duration, Instant};

    let mut args = std::env::args().skip(1);
    let seconds: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(5);
    let path = args.next().unwrap_or_else(|| "bench.h264".to_string());
    let synthetic = std::env::args().any(|a| a == "--synthetic");

    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let mut capturer = sidgate_capture::Capturer::new(0)?;
    let desktop = capturer.desktop();
    let config = EncoderConfig {
        width: desktop.width,
        height: desktop.height,
        framerate: 60,
        bitrate: 0,
    }
    .scale_bitrate_to_resolution(20_000_000);

    println!(
        "capture {}x{} -> H.264 {} kbit/s",
        config.width,
        config.height,
        config.bitrate / 1000
    );

    let mut encoder = Encoder::new(
        capturer.device(),
        capturer.context(),
        capturer.target_texture(),
        config,
    )?;

    let mut file = std::io::BufWriter::new(std::fs::File::create(&path)?);
    let mut frames: Vec<EncodedFrame> = Vec::with_capacity(8);
    let (mut captured, mut encoded, mut idle, mut bytes, mut keyframes) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut encode_total = Duration::ZERO;

    let start = Instant::now();
    if synthetic {
        // Une première acquisition remplit la texture, puis on encode en boucle.
        let deadline = Duration::from_secs(seconds);
        let _ = capturer.acquire(Duration::from_millis(200))?;
        while start.elapsed() < deadline {
            let mark = Instant::now();
            if encoder.submit(start.elapsed(), &mut frames)? == Submission::Accepted {
                captured += 1;
            }
            encode_total += mark.elapsed();
            for frame in frames.drain(..) {
                encoded += 1;
                bytes += frame.data.len() as u64;
                keyframes += u64::from(frame.keyframe);
                file.write_all(&frame.data)?;
            }
        }
    }
    while !synthetic && start.elapsed() < Duration::from_secs(seconds) {
        match capturer.acquire(Duration::from_millis(100))? {
            FrameStatus::Ready { .. } => {
                captured += 1;
                let mark = Instant::now();
                encoder.submit(start.elapsed(), &mut frames)?;
                encode_total += mark.elapsed();
            }
            FrameStatus::Idle => {
                idle += 1;
                encoder.poll(&mut frames)?;
            }
        }
        for frame in frames.drain(..) {
            encoded += 1;
            bytes += frame.data.len() as u64;
            keyframes += u64::from(frame.keyframe);
            file.write_all(&frame.data)?;
        }
    }
    file.flush()?;

    let elapsed = start.elapsed().as_secs_f64();
    println!("images capturées : {captured} ({:.1} i/s)", captured as f64 / elapsed);
    println!("images encodées  : {encoded} (dont {keyframes} clés)");
    println!("cycles à vide    : {idle}");
    println!("débit mesuré     : {:.2} Mbit/s", bytes as f64 * 8.0 / elapsed / 1e6);
    if captured > 0 {
        let t = encoder.take_timings();
        let per = |d: std::time::Duration| d.as_secs_f64() * 1000.0 / captured as f64;
        println!(
            "encodage moyen   : {:.2} ms/image",
            encode_total.as_secs_f64() * 1000.0 / captured as f64
        );
        println!(
            "  dont conversion {:.2} ms | soumission {:.2} ms | refus ASIC {}",
            per(t.convert),
            per(t.process),
            t.dropped
        );
    }
    println!("écrit dans {path}");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("banc d'essai disponible uniquement sous Windows");
}
