use clap::Parser;
fn main() {
    let code = match runboundary::cli::execute(runboundary::cli::Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("RunBoundary: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
