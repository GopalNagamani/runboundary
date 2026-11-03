use clap::Parser;
fn main() {
    let code = match agentvault::cli::execute(agentvault::cli::Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("AgentVault: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
