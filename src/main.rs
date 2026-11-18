//! Entry point: no arguments opens the window (feature `gui`), anything else is the command line.
fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(epma_usb_creator::cli::main(&argv));
}
