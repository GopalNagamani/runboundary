pub mod audit;
pub mod auth;
pub mod doctor;
pub mod init;
pub mod ios_build;
pub mod preview;
pub mod review;
pub mod run;
pub mod tools;
mod update;
pub mod xcode_register;
pub mod xib_compile;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    name = "runb",
    version,
    about = "Fail-closed Linux and macOS filesystem sandbox for coding agents",
    after_help = "Getting started (run from your project's directory):\n  runb init\n  runb doctor\n\nDiscover commands:\n  runb help run\n  runb help preview\n  runb help review\n  runb help xcode-register\n\nEach command also accepts --help. Run prints the retained session ID and next steps.\nUse --project PATH when running from another directory."
)]
pub struct Cli {
    #[arg(long, global = true, default_value = ".")]
    pub project: PathBuf,
    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand)]
pub enum Commands {
    /// Check the npm preview and offer to install a newer version.
    Update {
        /// Only report the available version.
        #[arg(long)]
        check: bool,
    },
    #[command(hide = true)]
    RefreshUpdates,
    /// Save or remove explicit login adapter approval.
    Auth {
        #[command(subcommand)]
        command: auth::AuthCommand,
    },
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
        after_help = "Requires a pending RunBoundary session, configured Xcode toolchain, and an explicitly approved installed Simulator runtime. Output must be a new workspace-relative .nib path with an existing parent. Only the isolated compiler receives the launch-helper connection. This does not integrate xcodebuild/storyboards or certify all Simulator service operations."
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
        /// Agent executable to check (defaults to codex).
        agent: Option<String>,
        /// Specify the agent by flag instead of position.
        #[arg(long = "agent", conflicts_with = "agent")]
        agent_option: Option<String>,
        #[arg(long)]
        auth_env: Vec<String>,
        /// Explicitly approve the file-backed ChatGPT login at ~/.codex/auth.json.
        #[arg(long, conflicts_with_all = ["auth_env", "codex_auth_file", "auth_adapter"])]
        chatgpt: bool,
        /// Explicitly approve a file-backed Codex ChatGPT login (never a whole directory).
        #[arg(long, conflicts_with = "auth_env")]
        codex_auth_file: Option<PathBuf>,
        /// Explicit private manifest mapping agent login/cache files into disposable HOME.
        #[arg(long, conflicts_with_all = ["codex_auth_file", "auth_env"])]
        auth_adapter: Option<PathBuf>,
        /// Ignore a previously approved adapter for this invocation.
        #[arg(long, conflicts_with = "auth_adapter")]
        no_saved_auth: bool,
    },
    /// Run an agent in a copied workspace with mandatory platform isolation.
    Run {
        /// Explicit approval to apply the summarized session changes after successful agent exit.
        #[arg(long)]
        apply: bool,
        /// Approve ONLY a named provider API key from the host environment.
        #[arg(long)]
        auth_env: Vec<String>,
        /// Explicitly approve the file-backed ChatGPT login at ~/.codex/auth.json.
        #[arg(long, conflicts_with_all = ["auth_env", "codex_auth_file", "auth_adapter"])]
        chatgpt: bool,
        /// Explicitly approve a file-backed Codex ChatGPT login (never a whole directory).
        #[arg(long, conflicts_with = "auth_env")]
        codex_auth_file: Option<PathBuf>,
        /// Explicit private manifest mapping agent login/cache files into disposable HOME.
        #[arg(long, conflicts_with_all = ["codex_auth_file", "auth_env"])]
        auth_adapter: Option<PathBuf>,
        /// Ignore a previously approved adapter for this invocation.
        #[arg(long, conflicts_with = "auth_adapter")]
        no_saved_auth: bool,
        /// Agent executable (for example, codex or claude), followed by any agent arguments.
        #[arg(required = true, trailing_var_arg = true)]
        agent: Vec<String>,
    },
    /// Show the changes in a retained session.
    Diff { session: String },
    /// Explicitly apply a retained session to the original project.
    Apply { session: String },
    /// Review a retained session and explicitly approve synchronization.
    Review {
        session: String,
        #[arg(long)]
        apply: bool,
        /// Show file changes before approving; --diff remains supported.
        #[arg(long, visible_alias = "review")]
        diff: bool,
    },
    /// Safely restore the original project state after an interrupted apply.
    Recover {
        /// Recovery directory printed by review/apply (basename or direct project path).
        recovery_dir: PathBuf,
    },
    /// Register files in a retained Xcode project's navigator (no target membership).
    #[command(
        after_help = "Examples (from the original project's directory):\n  runb xcode-register SESSION --xcode-project App.xcodeproj -- output.txt\n  runb xcode-register SESSION --xcode-project App.xcodeproj --new-files\n\nClose Xcode before editing its project metadata. Use a pending RunBoundary session ID,\nnot a Codex conversation ID. Register before review --apply; approval closes the session.\nRegistration changes only the retained copy's navigator references, not target membership."
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
        after_help = "Examples (from the original project's directory):\n  runb preview SESSION npm test\n  runb preview SESSION cargo test\n  runb preview SESSION --allow-network-listen --port 5173 npm run dev -- --host 127.0.0.1 --port 5173\n\nUse the RunBoundary session ID printed after run. Preview does not apply changes.\nNetwork listener approval is explicit; --port does not enforce a firewall rule."
    )]
    Preview {
        session: String,
        /// Expected app port for the preview URL; not a firewall rule (repeatable).
        #[arg(long, requires = "allow_network_listen", value_parser = clap::value_parser!(u16).range(1..))]
        port: Vec<u16>,
        /// Permit TCP listeners; Seatbelt cannot confine them to loopback/selected ports.
        #[arg(long)]
        allow_network_listen: bool,
        #[arg(required = true, trailing_var_arg = true)]
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
    if let Commands::Update { check } = &cli.command {
        update::execute(*check)?;
        return Ok(0);
    }
    if matches!(&cli.command, Commands::RefreshUpdates) {
        let _ = update::refresh();
        return Ok(0);
    }
    if let Commands::Auth { command } = &cli.command {
        auth::execute(command)?;
        return Ok(0);
    }
    if let Commands::IbtoolClient { bridge, arguments } = &cli.command {
        return crate::ib_bridge::client::execute(bridge, arguments);
    }
    if let Commands::ActoolClient { bridge, arguments } = &cli.command {
        return crate::ib_bridge::client::execute_assets(bridge, arguments);
    }
    if matches!(
        &cli.command,
        Commands::Init { .. } | Commands::Doctor { .. } | Commands::Run { .. }
    ) {
        update::notice();
    }
    let root = cli.project.canonicalize()?;
    let record_failure = matches!(
        &cli.command,
        Commands::Run { .. }
            | Commands::Doctor { .. }
            | Commands::Diff { .. }
            | Commands::Apply { .. }
            | Commands::Review { .. }
            | Commands::Recover { .. }
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
        Commands::Auth { .. }
        | Commands::Update { .. }
        | Commands::RefreshUpdates
        | Commands::IbtoolClient { .. }
        | Commands::ActoolClient { .. } => {
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
            agent_option,
            auth_env,
            chatgpt,
            codex_auth_file,
            auth_adapter,
            no_saved_auth,
        } => {
            let agent = agent.or(agent_option).unwrap_or_else(|| "codex".into());
            let codex_auth_file = auth::codex_file(&agent, chatgpt, codex_auth_file)?;
            let auth_adapter = auth::selected(
                &agent,
                auth_adapter,
                codex_auth_file.is_some() || !auth_env.is_empty(),
                no_saved_auth,
            )?;
            doctor::execute_with_adapter(
                &root,
                &agent,
                &auth_env,
                codex_auth_file.as_deref(),
                auth_adapter.as_deref(),
            )?;
            Ok(0)
        }
        Commands::Run {
            apply,
            auth_env,
            chatgpt,
            codex_auth_file,
            auth_adapter,
            no_saved_auth,
            agent,
        } => {
            let executable = agent
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing agent"))?;
            let mut codex_auth_file = auth::codex_file(executable, chatgpt, codex_auth_file)?;
            let auth_adapter = auth::selected(
                executable,
                auth_adapter,
                codex_auth_file.is_some() || !auth_env.is_empty(),
                no_saved_auth,
            )?;
            if agent.len() == 1
                && std::path::Path::new(executable).file_name()
                    == Some(std::ffi::OsStr::new("codex"))
                && auth_env.is_empty()
                && codex_auth_file.is_none()
                && auth_adapter.is_none()
                && !no_saved_auth
            {
                codex_auth_file = match auth::interactive_chatgpt_file()? {
                    Some(file) if auth::confirm_chatgpt()? => Some(file),
                    Some(_) => return Ok(0),
                    None => None,
                };
            }
            run::execute_with_adapter(
                &root,
                apply,
                &auth_env,
                &agent,
                codex_auth_file.as_deref(),
                auth_adapter.as_deref(),
            )
        }
        Commands::Diff { session } => {
            review::execute(&root, &session, false, true)?;
            Ok(0)
        }
        Commands::Apply { session } => {
            review::execute(&root, &session, true, false)?;
            Ok(0)
        }
        Commands::Review {
            session,
            apply,
            diff,
        } => {
            review::execute(&root, &session, apply, diff)?;
            Ok(0)
        }
        Commands::Recover { recovery_dir } => {
            let dir = crate::security::paths::Dir::open(&root)?;
            let config = crate::policy::config::Config::load(&root)?;
            let matcher = crate::policy::matcher::Matcher::new(&config)?;
            if crate::workspace::sync::recover(&root, &dir, &recovery_dir, &matcher)? {
                crate::security::audit::log(
                    &root,
                    "sync_recovered",
                    "restored pre-apply project state from a validated recovery journal",
                )?;
                println!("Recovered project files from {:?}.", recovery_dir);
            } else {
                println!(
                    "Recovery journal is already complete or recovered; no project files changed."
                );
            }
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
