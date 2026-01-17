// Copyright (c) 2024-present, fjall-rs
// This source code is licensed under both the Apache 2.0 and MIT License
// (found in the LICENSE-* files in the repository)

//! CLI tool for interacting with fjall databases

mod tool_cli;
use tool_cli::cli_main;
mod tool_cmd;

fn main() {
    // TODO: Exit values for non-interactive mode
    cli_main();
}
