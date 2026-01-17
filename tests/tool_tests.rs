// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

#![cfg(feature = "tool")]

//! Integration tests for the `fjall` CLI tool binary.
//!
//! These tests run the actual binary and verify its behavior.
//! The tool uses a keyspace-based architecture where operations require
//! a keyspace to be selected first.

use std::io::Write;
use std::process::{Command, Stdio};

/// Get the path to the fjall binary
fn fjall_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps
    path.push("fjall");
    path
}

/// Run the fjall binary in shell mode with piped input
fn run_shell(db_path: &std::path::Path, input: &str) -> (String, String, bool) {
    let mut child = Command::new(fjall_binary())
        .arg(db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn fjall binary");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("Failed to write to stdin");
    }

    let output = child.wait_with_output().expect("Failed to read output");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

/// Create a temporary directory for test databases
fn temp_db() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp dir")
}

// ============================================================================
// Basic Shell Tests
// ============================================================================

#[test]
fn test_shell_create_keyspace_and_set_get() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    // Create keyspace, cd into it, set and get
    let (stdout, stderr, success) = run_shell(
        &db_path,
        "mkdir myks\ncd myks\nset mykey myvalue\nget mykey\nexit\n",
    );

    assert!(success, "Shell failed: stderr={}", stderr);
    assert!(
        stdout.contains("created keyspace"),
        "Expected keyspace creation: {}",
        stdout
    );
    assert!(stdout.contains("OK"), "Expected OK for set: {}", stdout);
    assert!(
        stdout.contains("myvalue"),
        "Expected to get myvalue: {}",
        stdout
    );
}

#[test]
fn test_shell_get_nonexistent_key() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, stderr, success) =
        run_shell(&db_path, "mkdir myks\ncd myks\nget nonexistent\nexit\n");

    assert!(success, "Shell failed: stderr={}", stderr);
    assert!(
        stderr.contains("not found") || stdout.contains("not found"),
        "Expected 'not found': stdout={}, stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn test_shell_pwd() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(&db_path, "pwd\nmkdir myks\ncd myks\npwd\nexit\n");

    assert!(success);
    assert!(stdout.contains("/"), "Expected root path: {}", stdout);
    assert!(
        stdout.contains("/myks") || stdout.contains("myks"),
        "Expected /myks path: {}",
        stdout
    );
}

#[test]
fn test_shell_cd_to_root() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) =
        run_shell(&db_path, "mkdir myks\ncd myks\npwd\ncd\npwd\nexit\n");

    assert!(success);
    // Should show /myks then /
    assert!(
        stdout.contains("myks"),
        "Expected myks in output: {}",
        stdout
    );
}

#[test]
fn test_shell_flush() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(&db_path, "flush\nexit\n");

    assert!(success);
    assert!(
        stdout.contains("OK (flushed)"),
        "Expected flushed: {}",
        stdout
    );
}

#[test]
fn test_shell_exit_flushes() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    // Set value and exit (should flush)
    run_shell(
        &db_path,
        "mkdir myks\ncd myks\nset persistent_key persistent_value\nexit\n",
    );

    // Reopen and verify data persisted
    let (stdout, stderr, success) = run_shell(&db_path, "cd myks\nget persistent_key\nexit\n");
    assert!(success, "Shell failed: stderr={}", stderr);
    assert!(
        stdout.contains("persistent_value"),
        "Data should persist after exit: {}",
        stdout
    );
}

#[test]
fn test_shell_quit_alias() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(&db_path, "quit\n");
    assert!(success);
    assert!(
        stdout.contains("OK (flushed)"),
        "Expected flushed on quit: {}",
        stdout
    );
}

#[test]
fn test_shell_multiple_flush_calls() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(&db_path, "flush\nflush\nflush\nexit\n");

    assert!(success);
    let flush_count = stdout.matches("OK (flushed)").count();
    assert!(
        flush_count >= 3,
        "Should have multiple flush OKs: {}",
        stdout
    );
}

#[test]
fn test_shell_empty_lines() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(
        &db_path,
        "\n\nmkdir myks\n\ncd myks\n\nset key1 value1\n\nget key1\n\nexit\n",
    );

    assert!(success);
    assert!(stdout.contains("OK"), "Set should succeed: {}", stdout);
    assert!(
        stdout.contains("value1"),
        "Get should return value: {}",
        stdout
    );
}

#[test]
fn test_shell_quoted_values() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(
        &db_path,
        "mkdir myks\ncd myks\nset mykey \"hello world with spaces\"\nget mykey\nexit\n",
    );

    assert!(success);
    assert!(
        stdout.contains("hello world with spaces"),
        "Expected quoted value: {}",
        stdout
    );
}

#[test]
fn test_shell_single_quotes() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(
        &db_path,
        "mkdir myks\ncd myks\nset mykey 'single quoted value'\nget mykey\nexit\n",
    );

    assert!(success);
    assert!(
        stdout.contains("single quoted value"),
        "Expected single quoted value: {}",
        stdout
    );
}

#[test]
fn test_shell_overwrite_key() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(
        &db_path,
        "mkdir myks\ncd myks\nset mykey original\nset mykey updated\nget mykey\nexit\n",
    );

    assert!(success);
    assert!(
        stdout.contains("updated"),
        "Should show updated value: {}",
        stdout
    );
}

#[test]
fn test_shell_absolute_path_get() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    // Set via absolute path, get via absolute path
    let (stdout, _stderr, success) = run_shell(
        &db_path,
        "mkdir myks\nset /myks/testkey testvalue\nget /myks/testkey\nexit\n",
    );

    assert!(success);
    assert!(
        stdout.contains("testvalue"),
        "Expected testvalue: {}",
        stdout
    );
}

#[test]
fn test_shell_compact_requires_keyspace() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, stderr, success) = run_shell(&db_path, "compact\nexit\n");

    assert!(success);
    // Should show error about no keyspace selected
    assert!(
        stderr.contains("no keyspace") || stdout.contains("no keyspace"),
        "Expected no keyspace error: stdout={}, stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn test_shell_compact_with_keyspace() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, stderr, success) = run_shell(&db_path, "mkdir myks\ncd myks\ncompact\nexit\n");

    assert!(success, "Shell failed: stderr={}", stderr);
    assert!(
        stdout.contains("compacted"),
        "Expected compacted: {}",
        stdout
    );
}

#[test]
fn test_shell_compact_all() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, stderr, success) = run_shell(&db_path, "mkdir ks1\nmkdir ks2\ncompact -a\nexit\n");

    assert!(success, "Shell failed: stderr={}", stderr);
    assert!(
        stdout.contains("compacted"),
        "Expected compacted: {}",
        stdout
    );
}

#[test]
fn test_shell_compact_by_path() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, stderr, success) = run_shell(&db_path, "mkdir myks\ncompact /myks\nexit\n");

    assert!(success, "Shell failed: stderr={}", stderr);
    assert!(
        stdout.contains("compacted"),
        "Expected compacted: {}",
        stdout
    );
}

#[test]
fn test_shell_info() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, _stderr, success) = run_shell(&db_path, "info\nexit\n");

    assert!(success);
    assert!(
        stdout.contains("Database Information") || stdout.contains("Path:"),
        "Expected info output: {}",
        stdout
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_unclosed_quote_error() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (_stdout, stderr, success) =
        run_shell(&db_path, "mkdir myks\ncd myks\nset key \"unclosed\nexit\n");

    assert!(success);
    assert!(
        stderr.contains("unclosed quote"),
        "Should error on unclosed quote: {}",
        stderr
    );
}

#[test]
fn test_unknown_command_error() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (_stdout, stderr, success) = run_shell(&db_path, "notacommand\nexit\n");

    assert!(success);
    assert!(
        stderr.contains("unrecognized subcommand") || stderr.contains("error"),
        "Should error on unknown command: {}",
        stderr
    );
}

#[test]
fn test_missing_argument_error() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (_stdout, stderr, success) =
        run_shell(&db_path, "mkdir myks\ncd myks\nset onlykey\nexit\n");

    assert!(success);
    assert!(
        stderr.contains("required") || stderr.contains("VALUE"),
        "Should error on missing argument: {}",
        stderr
    );
}

#[test]
fn test_get_without_keyspace_error() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (_stdout, stderr, success) = run_shell(&db_path, "get somekey\nexit\n");

    assert!(success);
    // When no keyspace exists, 'somekey' is interpreted as keyspace name,
    // and since there's no key component, we get "no key specified"
    assert!(
        stderr.contains("no key specified") || stderr.contains("does not exist"),
        "Should error about no key or nonexistent keyspace: {}",
        stderr
    );
}

#[test]
fn test_set_without_keyspace_error() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (_stdout, stderr, success) = run_shell(&db_path, "set somekey somevalue\nexit\n");

    assert!(success);
    // When no keyspace exists, 'somekey' is interpreted as keyspace name,
    // and since there's no key component, we get "no key specified"
    assert!(
        stderr.contains("no key specified") || stderr.contains("does not exist"),
        "Should error about no key or nonexistent keyspace: {}",
        stderr
    );
}

#[test]
fn test_cd_nonexistent_keyspace_error() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (_stdout, stderr, success) = run_shell(&db_path, "cd nonexistent\nexit\n");

    assert!(success);
    assert!(
        stderr.contains("does not exist") || stderr.contains("cannot open"),
        "Should error about nonexistent keyspace: {}",
        stderr
    );
}

// ============================================================================
// Help Tests
// ============================================================================

#[test]
fn test_shell_help_command() {
    let db = temp_db();
    let db_path = db.path().join("test.db");

    let (stdout, stderr, success) = run_shell(&db_path, "help\nexit\n");

    assert!(success);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("Available Commands")
            || combined.contains("get")
            || combined.contains("Commands:"),
        "Help should show commands: {}",
        combined
    );
}

// ============================================================================
// Interactive shell tests using rexpect (Unix only)
// ============================================================================

#[cfg(unix)]
mod tests_rexpect_unix_only {
    use super::{fjall_binary, temp_db};
    use rexpect::session::PtySession;

    /// Spawn an interactive shell session
    fn spawn_shell(db_path: &std::path::Path) -> Result<PtySession, rexpect::error::Error> {
        let binary = fjall_binary();
        let db_path_str = db_path.to_str().unwrap();
        let command = format!("sh -c '{} {}'", binary.to_str().unwrap(), db_path_str);
        rexpect::spawn(&command, Some(5000))
    }

    #[test]
    fn test_interactive_prompt() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        // Wait for welcome message and prompt
        p.exp_string("Welcome to the fjall shell")
            .expect("Failed to see welcome message");
        p.exp_string("Type 'help' for available commands")
            .expect("Failed to see help message");
        // Prompt format is fjall(dbname):path>
        p.exp_regex(r"fjall\(.*\):.*/> ")
            .expect("Failed to see prompt");

        // Send exit command
        p.send_line("exit")?;
        p.exp_string("OK (flushed)")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_basic_commands() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        // Skip welcome messages, wait for prompt
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Create keyspace
        p.send_line("mkdir testks")?;
        p.exp_string("created keyspace")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Change to keyspace
        p.send_line("cd testks")?;
        p.exp_regex(r"fjall\(.*\):.*/testks> ")?;

        // Test set command
        p.send_line("set testkey testvalue")?;
        p.exp_string("OK")?;
        p.exp_regex(r"fjall\(.*\):.*/testks> ")?;

        // Test get command
        p.send_line("get testkey")?;
        p.exp_string("testvalue")?;
        p.exp_regex(r"fjall\(.*\):.*/testks> ")?;

        // Exit
        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_flush() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Flush
        p.send_line("flush")?;
        p.exp_string("OK (flushed)")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_quit_alias() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Use quit instead of exit
        p.send_line("quit")?;
        p.exp_string("OK (flushed)")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_empty_lines() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Send empty line
        p.send_line("")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Send command after empty line
        p.send_line("flush")?;
        p.exp_string("OK (flushed)")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_info_command() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Run info
        p.send_line("info")?;
        p.exp_string("Database Information")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_error_handling() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Try invalid command
        p.send_line("notacommand")?;
        // Should show error but continue
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Try command with missing args
        p.send_line("mkdir")?;
        // Should show error but continue
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_compact() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Create keyspace
        p.send_line("mkdir myks")?;
        p.exp_string("created keyspace")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Compact by path
        p.send_line("compact myks")?;
        p.exp_string("compacted")?;
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }

    #[test]
    fn test_interactive_help_command() -> Result<(), rexpect::error::Error> {
        let db = temp_db();
        let db_path = db.path().join("test.db");

        let mut p = spawn_shell(&db_path).expect("Failed to spawn shell");

        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        // Send help command
        p.send_line("help")?;
        // Help output should appear, then back to prompt
        p.exp_regex(r"fjall\(.*\):.*/> ")?;

        p.send_line("exit")?;
        p.exp_eof()?;

        Ok(())
    }
}
