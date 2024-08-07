use std::{env, fs, io, process};

use tracing_subscriber::{EnvFilter, FmtSubscriber};
use ub2cb::{content_blocker, ublock};

fn main() {
    // Setup logging.
    let directives = env::var("RUST_LOG").unwrap_or("warn,ub2cb=info".into());
    let env_filter = EnvFilter::builder().parse_lossy(directives);
    FmtSubscriber::builder()
        .with_writer(io::stderr)
        .with_env_filter(env_filter)
        .with_line_number(true)
        .init();

    // Parse all uBlock filters.
    let mut rules = Vec::new();
    for path in env::args().skip(1) {
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(err) => {
                eprintln!("Invalid input file {path:?}: {err}");
                process::exit(1);
            },
        };

        let mut new_rules = ublock::parse(&content);
        rules.append(&mut new_rules);
    }

    // Write the WebKit content blocker format to STDOUT.
    if let Err(err) = content_blocker::write_json(&mut io::stdout(), rules) {
        eprintln!("Content blocker conversion failed: {err}");
        process::exit(2);
    }
}
