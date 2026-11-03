pub mod audit;
pub mod doctor;
pub mod init;
pub mod ios_build;
pub mod preview;
pub mod review;
pub mod run;
pub mod tools;
pub mod xcode_register;
pub mod xib_compile;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "Fail-closed Linux and macOS filesystem sandbox for coding agents",
    after_help = "Getting started (run from your project's directory):\n  agentvault init\n  agentvault doctor\n\nDiscover commands:\n  agentvault help run\n  agentvault help preview\n  agentvault help review\n  agentvault help xcode-register\n\nEach command also accepts --help. Run prints the retained session ID and next steps.\nUse --project PATH when running from another directory."
)]
pub struct Cli {
    #[arg(long, global = true, default_value = ".")]
    pub project: PathBuf,
    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand)]
pub enum Commands {
    /// Experimental unsigned Simulator build with constrained IB and asset compiler IPC.
    IosBuild {
        /// Pending session; omit to build a fresh filtered copy of the project.
        session: Option<String>,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        scheme: String,
        #[arg(long)]
        simulator_runtime: PathBuf,
        /// Permit only the isolated compiler to contact shared Simulator services.
        /// These services have host account authority and may create build devices.
        #[arg(long)]
        allow_compiler_simulator_services: bool,
    },
    #[command(hide = true)]
    IbtoolClient {
        #[arg(long)]
        bridge: PathBuf,
        #[arg(last = true, allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
    #[command(hide = true)]
    ActoolClient {
        #[arg(long)]
        bridge: PathBuf,
        #[arg(last = true, allow_hyphen_values = true)]
        arguments: Vec<String>,
    },
    /// Experimental: compile one retained XIB through a separate, constrained compiler sandbox.
    #[command(
        after_help = "Requires a pending AgentVault session, configured Xcode toolchain, and an explicitly approved installed Simulator runtime. Output must be a new workspace-relative .nib path with an existing parent. Only the isolated compiler receives the launch-helper connection. This does not integrate xcodebuild/storyboards or certify all Simulator service operations."
    )]
    XibCompile {
        session: String,
        #[arg(long)]
        simulator_runtime: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        module: Option<String>,
        #[arg(long, default_value = "17.2")]
        deployment_target: String,
    },
    /// Create a secure policy without inspecting secret contents.
    Init {
        /// Explicitly approve an additional read-only macOS runtime tree, e.g. /opt/homebrew.
        #[arg(long)]
        runtime_root: Vec<PathBuf>,
    },
    /// Probe platform sandbox controls, runtime availability, and authentication setup.
    Doctor {
        #[arg(long, default_value = "codex")]
        agent: String,
        #[arg(long)]
        auth_env: Vec<String>,
        /// Explicitly approve a file-backed Codex ChatGPT login (never a whole directory).
        #[arg(long, conflicts_with = "auth_env")]
        codex_auth_file: Option<PathBuf>,
    },
    /// Run an agent in a copied workspace with mandatory platform isolation.
    Run {
        /// Explicit approval to apply the summarized session changes after successful agent exit.
        #[arg(long)]
        apply: bool,
        /// Approve ONLY a named provider API key from the host environment.
        #[arg(long)]
        auth_env: Vec<String>,
        /// Explicitly approve a file-backed Codex ChatGPT login (never a whole directory).
        #[arg(long, conflicts_with = "auth_env")]
        codex_auth_file: Option<PathBuf>,
        #[arg(required = true, last = true)]
        agent: Vec<String>,
    },
    /// Review a retained session and explicitly approve synchronization.
    Review {
        session: String,
        #[arg(long)]
        apply: bool,
        /// Show file changes before approving; --diff remains supported.
        #[arg(long, visible_alias = "review")]
        diff: bool,
    },
    /// Register files in a retained Xcode project's navigator (no target membership).
    #[command(
        after_help = "Examples (from the original project's directory):\n  agentvault xcode-register SESSION --xcode-project App.xcodeproj -- output.txt\n  agentvault xcode-register SESSION --xcode-project App.xcodeproj --new-files\n\nClose Xcode before editing its project metadata. Use a pending AgentVault session ID,\nnot a Codex conversation ID. Register before review --apply; approval closes the session.\nRegistration changes only the retained copy's navigator references, not target membership."
    )]
    XcodeRegister {
        session: String,
        #[arg(long)]
        xcode_project: PathBuf,
        /// Discover all files added during this session.
        #[arg(long, conflicts_with = "files")]
        new_files: bool,
        /// Workspace-relative files to register; use -- before the filenames.
        #[arg(last = true, required_unless_present = "new_files")]
        files: Vec<PathBuf>,
    },
    /// Run or test retained changes inside the sandbox before approving them.
    #[command(
        after_help = "Examples (from the original project's directory):\n  agentvault preview SESSION -- npm test\n  agentvault preview SESSION -- cargo test\n  agentvault preview SESSION --allow-network-listen --port 5173 -- npm run dev -- --host 127.0.0.1 --port 5173\n\nUse the AgentVault session ID printed after run. Preview does not apply changes.\nNetwork listener approval is explicit; --port does not enforce a firewall rule."
    )]
    Preview {
        session: String,
        /// Expected app port for the preview URL; not a firewall rule (repeatable).
        #[arg(long, requires = "allow_network_listen", value_parser = clap::value_parser!(u16).range(1..))]
        port: Vec<u16>,
        /// Permit TCP listeners; Seatbelt cannot confine them to loopback/selected ports.
        #[arg(long)]
        allow_network_listen: bool,
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Inspect project/toolchain configuration; optionally run sandboxed version checks.
    Tools {
        #[arg(long)]
        check: bool,
    },
    /// Display observed lifecycle and policy decisions as JSONL.
    Audit,
}
pub fn execute(cli: Cli) -> anyhow::Result<i32> {
    if let Commands::IbtoolClient { bridge, arguments } = &cli.command {
        return crate::ib_bridge::client::execute(bridge, arguments);
    }
    if let Commands::ActoolClient { bridge, arguments } = &cli.command {
        return crate::ib_bridge::client::execute_assets(bridge, arguments);
    }
    let root = cli.project.canonicalize()?;
    let record_failure = matches!(
        &cli.command,
        Commands::Run { .. }
            | Commands::Doctor { .. }
            | Commands::Review { .. }
            | Commands::Preview { .. }
            | Commands::Tools { .. }
            | Commands::XcodeRegister { .. }
            | Commands::XibCompile { .. }
            | Commands::IosBuild { .. }
    );
    let result = execute_inner(cli);
    if record_failure && result.is_err() {
        let _=crate::security::audit::log(&root,"command_refused","policy, prerequisite, execution, or synchronization check failed; no unsandboxed fallback");
    }
    result
}
fn execute_inner(cli: Cli) -> anyhow::Result<i32> {
    let root = cli.project.canonicalize()?;
    match cli.command {
        Commands::IosBuild {
            session,
            workspace,
            scheme,
            simulator_runtime,
            allow_compiler_simulator_services,
        } => ios_build::execute(
            &root,
            session.as_deref(),
            &workspace,
            &scheme,
            &simulator_runtime,
            allow_compiler_simulator_services,
        ),
        Commands::IbtoolClient { .. } | Commands::ActoolClient { .. } => {
            unreachable!("internal client dispatch occurs before project access")
        }
        Commands::XibCompile {
            session,
            simulator_runtime,
            input,
            output,
            module,
            deployment_target,
        } => xib_compile::execute(
            &root,
            &session,
            &simulator_runtime,
            &input,
            &output,
            module,
            deployment_target,
        ),
        Commands::Init { runtime_root } => {
            init::execute(&root, runtime_root)?;
            Ok(0)
        }
        Commands::Doctor {
            agent,
            auth_env,
            codex_auth_file,
        } => {
            doctor::execute(&root, &agent, &auth_env, codex_auth_file.as_deref())?;
            Ok(0)
        }
        Commands::Run {
            apply,
            auth_env,
            codex_auth_file,
            agent,
        } => run::execute(&root, apply, &auth_env, &agent, codex_auth_file.as_deref()),
        Commands::Review {
            session,
            apply,
            diff,
        } => {
            review::execute(&root, &session, apply, diff)?;
            Ok(0)
        }
        Commands::Preview {
            session,
            port,
            allow_network_listen,
            command,
        } => preview::execute(&root, &session, &port, &command, allow_network_listen),
        Commands::XcodeRegister {
            session,
            xcode_project,
            new_files,
            files,
        } => {
            xcode_register::execute(&root, &session, &xcode_project, new_files, &files)?;
            Ok(0)
        }
        Commands::Tools { check } => tools::execute(&root, check),
        Commands::Audit => {
            audit::execute(&root)?;
            Ok(0)
        }
    }
}
