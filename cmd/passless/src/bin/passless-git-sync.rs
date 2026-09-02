use prs_lib::Store;
use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let action = required_arg(&mut args, "action")?;
    let store_path = required_arg(&mut args, "store path")?;

    let store = Store::open(store_path.to_string_lossy().as_ref())
        .map_err(|error| format!("failed to open password store: {error:?}"))?;

    match action.to_str() {
        Some("prepare") => {
            reject_extra_args(&mut args)?;
            store
                .sync()
                .prepare()
                .map_err(|error| format!("prepare failed: {error:?}"))
        }
        Some("finalize") => {
            let message = required_arg(&mut args, "commit message")?;
            reject_extra_args(&mut args)?;
            let message = message
                .into_string()
                .map_err(|_| "commit message is not valid UTF-8".to_string())?;
            store
                .sync()
                .finalize(message)
                .map_err(|error| format!("finalize failed: {error:?}"))
        }
        _ => Err("action must be either 'prepare' or 'finalize'".to_string()),
    }
}

fn required_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<OsString, String> {
    args.next().ok_or_else(|| format!("missing {name}"))
}

fn reject_extra_args(args: &mut impl Iterator<Item = OsString>) -> Result<(), String> {
    if args.next().is_some() {
        Err("unexpected extra argument".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_arg_rejects_missing_value() {
        let mut args = Vec::<OsString>::new().into_iter();
        assert_eq!(
            required_arg(&mut args, "store path").unwrap_err(),
            "missing store path"
        );
    }

    #[test]
    fn reject_extra_args_accepts_empty_iterator() {
        let mut args = Vec::<OsString>::new().into_iter();
        assert!(reject_extra_args(&mut args).is_ok());
    }
}
