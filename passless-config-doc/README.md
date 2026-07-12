# passless-config-doc

Procedural macro to generate documented configuration files for Passless.

This crate provides the `#[derive(ConfigDoc)]` macro that extracts documentation from struct field
doc comments and generates TOML configuration files with inline documentation.

## Usage

```rust
use passless_config_doc::ConfigDoc;

#[derive(ConfigDoc)]
struct MyConfig {
    /// This is a documented field
    #[default("default_value".to_string())]
    pub field: String,
}
```

This macro is specifically designed for use with the [Passless](https://github.com/pando85/passless)
FIDO2 authenticator.
