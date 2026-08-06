use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    match agent_principal_probe::build_report(&args) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{}", json);
            }
            Err(e) => {
                eprintln!("probe: serialization error: {}", e);
                process::exit(2);
            }
        },
        Err(e) => {
            eprintln!("probe: {}", e);
            process::exit(1);
        }
    }
}
