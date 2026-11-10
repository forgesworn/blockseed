//! `cargo run --features fetch --example today`
use blockseed::resolve::CrossCheck;

fn main() {
    match blockseed::http::fetch_today(b"blockseed-example-v1") {
        Ok(o) => {
            println!("day         {}", o.daily.day);
            println!("height      {}", o.daily.height);
            println!("hash        {}", o.daily.hash_hex);
            println!("seed        {:#018x} ({})", o.daily.seed, o.daily.seed);
            match &o.cross_check {
                CrossCheck::Agreed => println!("cross-check blockstream.info agrees"),
                CrossCheck::Unreachable(e) => println!("cross-check second source unreachable: {e}"),
                CrossCheck::Failed(e) => println!("cross-check second source answered badly: {e}"),
                other => println!("cross-check {other:?}"),
            }
            println!("requests    {}", o.requests);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
