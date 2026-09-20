from pathlib import Path

path = Path("cmd/passless/src/storage/pass/mod.rs")
text = path.read_text()
old = "        self::init::ensure_initialized(&store_path, gpg_backend, allow_create_without_prompt)?;"
new = """        self::init::ensure_initialized(
            &store_path,
            &path,
            gpg_backend,
            allow_create_without_prompt,
        )?;"""
if text.count(old) != 1:
    raise SystemExit(f"expected one initialization call, found {text.count(old)}")
path.write_text(text.replace(old, new))
