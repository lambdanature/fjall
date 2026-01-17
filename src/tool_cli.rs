// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

// CLI for the fjall CLI tool

// TODO: remove these and fix the warnings instead
#![allow(unused_imports)]

use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use enquote;
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    prelude::*,
    registry::Registry,
};

use crate::tool_cmd::ShellSession;

#[macro_export]
macro_rules! die {
    ($fmt:literal, $($arg:tt)*) => {{
        eprintln!($fmt, $($arg)*);
        std::process::exit(1);
    }};

    ($msg:literal) => {{
        eprintln!($msg);
        std::process::exit(1);
    }};

    () => {{
        eprintln!("Program terminated unexpectedly");
        std::process::exit(1);
    }};
}

#[macro_export]
// There are multiple relevant crates, but this should suffice
macro_rules! pluralize {
    // Case 1: Word and Count (Simple "s" suffix)
    ($word:expr, $count:expr) => {
        if $count == 1 {
            $word.to_string()
        } else {
            format!("{}s", $word)
        }
    };

    // Case 2: Singular, Plural, and Count (Explicit forms)
    ($singular:expr, $plural:expr, $count:expr) => {
        if $count == 1 {
            $singular.to_string()
        } else {
            $plural.to_string()
        }
    };
}

pub fn init_tracing(quiet: bool, verbose: u8) -> (bool, LevelFilter) {
    let is_verbose = !quiet && verbose > 0;

    let level_filter = if quiet {
        LevelFilter::ERROR
    } else {
        match verbose {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    };

    // Bridge log crate macros to tracing (for library code that uses log::*)
    tracing_log::LogTracer::init().expect("Failed to set log tracer");

    let registry = Registry::default();

    let env_filter = EnvFilter::builder()
        .with_default_directive(level_filter.into())
        .with_env_var("FJALL_LOG")
        .from_env_lossy()
        .add_directive(
            "rustyline=warn"
                .parse()
                .expect("Failed to parse rustyline directive"),
        );

    let subscriber = registry.with(env_filter).with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .compact(),
    );

    if tracing::subscriber::set_global_default(subscriber).is_err() {
        die!("INTERNAL ERROR: setting default tracing::subscriber failed");
    }

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing_panic::panic_hook(info);
        prev_hook(info); // daisy-chain to old panic hook
    }));

    (is_verbose, level_filter)
}

fn parse_size_as_u32(s: &str) -> Result<u32, String> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s)
        .map(|size| size as u32)
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ShellMode {
    Unix,
    Windows,
}

/// CLI tool for interacting with fjall databases
#[derive(Parser, Debug)]
#[command(name = "fjall")]
#[command(about = "CLI tool for interacting with fjall databases")]
struct ToolArgs {
    /// Suppress all output except for errors. This overrides the -v flag.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Turn on verbose output. Supply -v multiple times to increase verbosity.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,

    /// Path to the fjall db directory (will be created if it doesn't exist)
    fjall_path: PathBuf,

    /// Shell mode, use shortcut -W to set Windows mode
    #[arg(
        long,
        short = 'M',
        global = true,
        default_value_if("windows", "true", Some("windows")),
        default_value_if("unix", "false", Some("unix")),
        default_value = "unix",
        overrides_with("windows"),
        overrides_with("unix")
    )]
    mode: ShellMode,

    /// Windows shell mode (\ as path separator and PowerShell-style escaping / quoting)
    #[arg(short = 'W', long, global = true)]
    windows: bool,

    /// Unix shell mode (/ as path separator and Shell-style escaping / quoting)
    #[arg(short = 'U', long, global = true)]
    unix: bool,
    /// Command to run (if omitted, starts interactive shell)
    #[command(subcommand)]
    command: Option<ToolCommand>,
}

#[derive(Subcommand, Debug, Clone)]
enum ToolCommand {
    // TODO: Copy (cp), Move (mv): transactional Copy + Del
    // TODO: Scan/Del: Ability to glob keys in addition to prefix scan
    /// Get the value for a key
    #[command(visible_alias = "cat")]
    Get {
        /// The key to look up
        key: String,

        /// Output value as hex bytes
        #[arg(short = 'C', long)]
        hex: bool,
    },
    /// Set a key-value pair
    Set {
        /// The key to set
        key: String,
        /// The value to store
        value: String,
    },
    /// Delete a key
    #[command(visible_alias = "rm")]
    Del {
        /// The key to delete
        key: String,

        /// Recursively delete all keys with this prefix
        #[arg(short, long)]
        recursive: bool,

        /// Print each key as it's deleted
        #[arg(short = 'p', long = "print")]
        print_keys: bool,

        /// Force deletion (required to delete an entire keyspace)
        #[arg(short, long)]
        force: bool,
    },
    /// List all keys, optionally filtered by prefix
    #[command(visible_alias = "list", visible_alias = "ls", visible_alias = "dir")]
    Scan {
        /// Optional prefix to filter keys
        prefix: Option<String>,

        /// Show internal key fields (seqno, value_type)
        #[arg(short = 'l', long = "long")]
        long: bool,

        /// Ignored (no hidden keys exist)
        #[arg(short = 'a', long = "all", hide = true)]
        _all: bool,
    },
    #[command(hide = true, alias = "ll", alias = "la")]
    ScanLong {
        /// Optional prefix to filter keys
        prefix: Option<String>,
    },
    /// List keys in a range [start, end)
    Range {
        /// Start of the range (inclusive)
        start: String,
        /// End of the range (exclusive)
        end: String,
    },
    /// Count the number of items
    Count,
    /// Flush memtable to disk
    Flush,
    /// Run major compaction
    Compact {
        /// Paths to keyspaces to compact (defaults to current keyspace)
        #[arg(conflicts_with = "all")]
        paths: Vec<String>,

        /// Compact all keyspaces
        #[arg(short, long, conflicts_with = "paths")]
        all: bool,
    },
    /// Show db statistics
    Info,
}

// Internal shell commands, include all external tool commands
#[derive(Parser, Debug)]
#[command(name = "")]
#[command(no_binary_name = true)]
#[command(disable_version_flag = true)]
#[command(help_template = "
{version}

Available Commands:

{subcommands}

Use `help COMMAND` or `COMMAND --help` for more details.

")]

struct ShellArgs {
    #[command(subcommand)]
    command: ShellCommand,
}

// Shell commands (including ones not available from CLI)
#[derive(Subcommand, Debug, Clone)]
enum ShellCommand {
    #[command(flatten)]
    ToolCmd(ToolCommand),

    /// Exit the current shell (with implicit flush)
    #[command(visible_alias = "quit")]
    Exit,
    /// Abort the curent shell (without flush)
    Abort,
    /// Begin a new batch (transaction)
    Begin,
    /// Commit the current batch
    Commit,
    /// Rollback (discard) the current batch
    Rollback,
    /// Print current working directory
    Pwd,
    /// Change current working directory
    Cd {
        /// Path to change to (absolute or relative)
        path: Option<String>,
    },
    /// Create a keyspace (mkdir)
    Mkdir {
        /// Path to create (first component is the keyspace name)
        path: String,
    },
}

/// A pending operation in a batch
#[derive(Debug, Clone)]
enum BatchOp {
    Set { key: String, value: String },
    Del { key: String },
}

/// A batch of pending operations
#[derive(Debug, Default)]
struct Batch {
    /// Operations in order they were added
    ops: Vec<BatchOp>,
    /// Current state of keys in the batch (for reads)
    state: HashMap<String, Option<String>>,
}

/// Result of executing a command
enum CommandResult {
    Continue,
    Exit,
}

/// Execute a parsed command
fn execute_command(
    session: &mut ShellSession,
    cmd: ToolCommand,
    auto_flush: bool,
) -> CommandResult {
    match cmd {
        ToolCommand::Get { key, hex } => session.handle_get(&key, hex),
        ToolCommand::Set { key, value } => session.handle_set(&key, &value, auto_flush),
        ToolCommand::Del {
            key,
            recursive,
            print_keys,
            force,
        } => session.handle_del(&key, recursive, print_keys, force, auto_flush),
        ToolCommand::Scan { prefix, long, _all } => session.handle_scan(prefix.as_deref(), long),
        ToolCommand::ScanLong { prefix } => session.handle_scan(prefix.as_deref(), true),
        ToolCommand::Range { start, end } => session.handle_range(&start, &end),
        ToolCommand::Count => session.handle_count(),
        ToolCommand::Flush => session.handle_flush(),
        ToolCommand::Compact { paths, all } => session.handle_compact(&paths, all),
        ToolCommand::Info => session.print_info(),
    }
    CommandResult::Continue
}

/// Execute a shell-only command
fn execute_shell_command(
    session: &mut ShellSession,
    cmd: ShellCommand,
    auto_flush: bool,
) -> CommandResult {
    match cmd {
        ShellCommand::ToolCmd(tool_cmd) => execute_command(session, tool_cmd, auto_flush),
        ShellCommand::Exit => {
            // if session.has_batch() {
            //     eprintln!("Warning: discarding uncommitted batch");
            //     session.rollback_batch();
            // }
            session.handle_flush();
            CommandResult::Exit
        }
        ShellCommand::Abort => {
            // if session.has_batch() {
            //     eprintln!("Warning: discarding uncommitted batch");
            // }
            CommandResult::Exit
        }
        ShellCommand::Begin => {
            // if session.begin_batch() {
            //     println!("OK (batch started)");
            // } else {
            //    eprintln!("Error: batch already active");
            // }
            CommandResult::Continue
        }
        ShellCommand::Commit => {
            // if session.commit_batch() {
            //    println!("OK (batch committed, ready to flush)");
            //} else {
            //    eprintln!("Error: no active batch");
            //}
            CommandResult::Continue
        }
        ShellCommand::Rollback => {
            //if session.rollback_batch() {
            //    println!("OK (batch rolled back)");
            //} else {
            //    eprintln!("Error: no active batch");
            //}
            CommandResult::Continue
        }
        ShellCommand::Pwd => {
            session.handle_pwd();
            CommandResult::Continue
        }
        ShellCommand::Cd { path } => {
            session.handle_cd(path.as_deref());
            CommandResult::Continue
        }
        ShellCommand::Mkdir { path } => {
            session.handle_mkdir(&path);
            CommandResult::Continue
        }
    }
}

/// Double every backslash in the input, except when the backslash is
/// followed by a shell quote character (' or ").
fn protect_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some(&'"') | Some(&'\'') => {
                    // Backslash before a quote character -- keep as-is
                    result.push('\\');
                }
                _ => {
                    // Double the backslash
                    result.push('\\');
                    result.push('\\');
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Parse and run a shell command line
fn run_shell_command(session: &mut ShellSession, line: &str) -> CommandResult {
    let line = line.trim();
    if line.is_empty() {
        return CommandResult::Continue;
    }

    let tokens = match session.mode {
        ShellMode::Windows => {
            // Use winsplit to parse Windows-style command line (VC++ 2008 rules)
            winsplit::split(line)
        }
        ShellMode::Unix => match shlex::split(&protect_escapes(line)) {
            Some(t) => t,
            Some(_) => return CommandResult::Continue,
            None => {
                eprintln!("error: unclosed quote");
                return CommandResult::Continue;
            }
        },
    };

    if tokens.is_empty() {
        return CommandResult::Continue;
    }

    let processed: Vec<String> = tokens
        .into_iter()
        .map(|s| enquote::unescape(&s, None).unwrap_or(s))
        .collect();

    // Parse remaining commands
    match ShellArgs::try_parse_from(&processed) {
        Ok(args) => execute_shell_command(session, args.command, false),
        Err(e) => {
            // Print clap's error message
            eprintln!("{}", e);
            CommandResult::Continue
        }
    }
}

fn run_shell(session: &mut ShellSession) {
    if io::stdin().is_terminal() {
        run_shell_interactive(session);
    } else {
        run_shell_non_interactive(session);
    }
}

fn run_shell_interactive(session: &mut ShellSession) {
    let filename: String = match session.path.file_name() {
        Some(filename) => filename.to_string_lossy().into_owned(),
        None => die!(
            "can't extract filename from path: {}",
            session.cwd.path().to_string_lossy()
        ),
    };

    println!("Welcome to the fjall shell");
    println!("Type 'help' for available commands, 'exit' to quit.\n");

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("Error initializing line editor: {}", e);
            return;
        }
    };

    loop {
        let prompt = format!(
            "fjall({filename}):{}> ",
            session.cwd.path().to_string_lossy()
        );
        match rl.readline(&prompt) {
            Ok(line) => {
                rl.add_history_entry(&line);
                if let CommandResult::Exit = run_shell_command(session, &line) {
                    break;
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                // Ignore Ctrl+C, just show a new prompt
                continue;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}

fn run_shell_non_interactive(session: &mut ShellSession) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        if stdout.flush().is_err() {
            die!("can't flush stdout");
        }

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(_) => {
                if let CommandResult::Exit = run_shell_command(session, &line) {
                    break;
                }
            }
            Err(e) => {
                die!("Error reading input: {}", e);
            }
        }
    }
}

pub fn cli_main() {
    let args = ToolArgs::parse();
    let (verbose, level_filter) = init_tracing(args.quiet, args.verbose);

    let cmd = ToolArgs::command();

    info!(
        "starting {} ({} {}), log level: {level_filter}",
        cmd.get_name(),
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let mode = if args.windows {
        ShellMode::Windows
    } else {
        args.mode
    };

    let mut session = match ShellSession::open(args.fjall_path, mode) {
        Ok(s) => s,
        Err(e) => {
            let note = if verbose {
                ""
            } else {
                ". Note: Use -v (one or multiple times) for more information"
            };
            die!("Error opening tree: {}{}", e, note);
        }
    };

    match args.command {
        Some(cmd) => {
            execute_command(&mut session, cmd, true);
        }
        None => run_shell(&mut session),
    }
}
