use clap::Parser;

/// A simple starter CLI application.
#[derive(Parser, Debug)]
#[command(name = "rs-bubble", version, about)]
struct Args {
    /// Name of the person to greet.
    #[arg(short, long, default_value = "world")]
    name: String,

    /// Increase verbosity (-v, -vv, ...).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let args = Args::parse();

    if args.verbose > 0 {
        println!("Parsed args: {args:?}");
    }

    println!("Hello, {}!", args.name);
}
