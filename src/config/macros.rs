//! Macros to reduce config boilerplate

/// Comprehensive macro to define a complete config with minimal repetition
///
/// This macro generates:
/// - Config struct with Field<State, T> types
/// - ConfigArgs struct with Option<T> types and clap attributes
/// - Default implementations
/// - Serialize/Deserialize for Raw state
/// - merge(), resolve(), and to_raw_config() methods
///
/// # Syntax
///
/// ```ignore
/// define_config! {
///     /// Config struct documentation
///     ConfigName / ConfigArgsName => group = "group_id" [, prefix = "prefix", env_prefix = "ENV_PREFIX"] {
///         $(
///             (field_name, "ENV_FIELD", "cli-name": FieldType = default_expr
///                 => "Field documentation"
///                 [, value_name = "VALUE_NAME"])
///         ),*
///     }
/// }
/// ```
///
/// - `group`: The clap group ID
/// - `prefix`: Optional CLI prefix for backend configs (e.g., "local" generates `--local-field`)
/// - `env_prefix`: Optional env prefix for backend configs (e.g., "LOCAL" generates `PASSLESS_LOCAL_FIELD`)
/// - `field_name`: Rust field name in snake_case
/// - `ENV_FIELD`: Uppercase field name for environment variable (e.g., "USE_MLOCK", "PATH")
/// - `cli-name`: Kebab-case name for the CLI argument (e.g., "use-mlock")
/// - `value_name`: Optional value name for clap (e.g., "PATH")
#[macro_export]
macro_rules! define_config {
    // Variant without prefix (for top-level configs like SecurityConfig)
    (
        $(#[$struct_doc:meta])*
        $config_name:ident / $args_name:ident => group = $group:literal {
            $(
                (
                    $field:ident, $env_field:literal, $cli_name:literal: $field_type:ty = $default:expr
                    => $doc:literal
                    $(, value_name = $value_name:literal)?
                )
            ),* $(,)?
        }
    ) => {
        $crate::define_config! {
            @impl
            $(#[$struct_doc])*
            $config_name / $args_name
            => group = $group, prefix = "", env_prefix = "", arg_id_prefix = ""
            {
                $(
                    ($field, $env_field, $cli_name: $field_type = $default
                        => $doc
                        $(, help = $doc)?
                        $(, value_name = $value_name)?)
                ),*
            }
        }
    };

    // Variant with only env_prefix (for non-backend configs like SecurityConfig)
    (
        $(#[$struct_doc:meta])*
        $config_name:ident / $args_name:ident => group = $group:literal, prefix = "", env_prefix = $env_prefix:literal {
            $(
                (
                    $field:ident, $env_field:literal, $cli_name:literal: $field_type:ty = $default:expr
                    => $doc:literal
                    $(, value_name = $value_name:literal)?
                )
            ),* $(,)?
        }
    ) => {
        $crate::define_config! {
            @impl
            $(#[$struct_doc])*
            $config_name / $args_name
            => group = $group, prefix = "", env_prefix = $env_prefix, arg_id_prefix = ""
            {
                $(
                    ($field, $env_field, $cli_name: $field_type = $default
                        => $doc
                        $(, value_name = $value_name)?)
                ),*
            }
        }
    };

    // Variant with prefix (for backend configs)
    (
        $(#[$struct_doc:meta])*
        $config_name:ident / $args_name:ident => group = $group:literal, prefix = $prefix:literal, env_prefix = $env_prefix:literal {
            $(
                (
                    $field:ident, $env_field:literal, $cli_name:literal: $field_type:ty = $default:expr
                    => $doc:literal
                    $(, value_name = $value_name:literal)?
                )
            ),* $(,)?
        }
    ) => {
        $crate::define_config! {
            @impl
            $(#[$struct_doc])*
            $config_name / $args_name
            => group = $group, prefix = $prefix, env_prefix = $env_prefix, arg_id_prefix = $prefix
            {
                $(
                    ($field, $env_field, $cli_name: $field_type = $default
                        => $doc
                        $(, value_name = $value_name)?)
                ),*
            }
        }
    };

    // Internal implementation — case: no arg_id_prefix (empty string)
    (
        @impl
        $(#[$struct_doc:meta])*
        $config_name:ident / $args_name:ident
        => group = $group:literal, prefix = $prefix:literal, env_prefix = $env_prefix:literal, arg_id_prefix = ""
        {
            $(
                ($field:ident, $env_field:literal, $cli_name:literal: $field_type:ty = $default:expr
                    => $doc:literal
                    $(, value_name = $value_name:literal)?)
            ),* $(,)?
        }
    ) => {
        // Generate the Config struct (same as before)
        $(#[$struct_doc])*
        #[derive(Debug, Clone)]
        pub struct $config_name<State: $crate::config::state::ConfigState = $crate::config::state::Resolved> {
            $(
                #[doc = $doc]
                pub $field: $crate::config::state::Field<State, $field_type>,
            )*
            pub(crate) _state: $crate::config::state::StateMarker<State>,
        }

        // For the no-prefix case we generate args struct without arg IDs
        $crate::define_config!(@gen_args_struct_no_prefix
            $args_name, $group, "", $env_prefix
            {
                $(
                    ($field, $env_field, $cli_name, $field_type, $doc
                        $(, value_name = $value_name)?)
                ),*
            }
        );

        // Default implementation for Config
        $crate::define_config!(@impl_default
            $config_name { $($field: $field_type),* }
        );

        // Serialize / Deserialize / merge / resolve / to_raw_config (same as before)
        $crate::impl_raw_serialize!($config_name { $($field),* });
        $crate::impl_raw_deserialize!($config_name { $($field: $field_type),* });
        $crate::impl_merge!($config_name { $($field),* });
        $crate::impl_resolve!($config_name { $($field => $default),* });
        $crate::impl_to_raw_config!($args_name => $config_name { $($field),* });
    };

    // Internal implementation — case: non-empty arg_id_prefix (prefix present)
    (
        @impl
        $(#[$struct_doc:meta])*
        $config_name:ident / $args_name:ident
        => group = $group:literal, prefix = $prefix:literal, env_prefix = $env_prefix:literal, arg_id_prefix = $arg_id_prefix:literal
        {
            $(
                ($field:ident, $env_field:literal, $cli_name:literal: $field_type:ty = $default:expr
                    => $doc:literal
                    $(, value_name = $value_name:literal)?)
            ),* $(,)?
        }
    ) => {
        // Generate the Config struct (same as before)
        $(#[$struct_doc])*
        #[derive(Debug, Clone)]
        pub struct $config_name<State: $crate::config::state::ConfigState = $crate::config::state::Resolved> {
            $(
                #[doc = $doc]
                pub $field: $crate::config::state::Field<State, $field_type>,
            )*
            pub(crate) _state: $crate::config::state::StateMarker<State>,
        }

        // For the prefixed case we include the prefix/env_prefix into each field tuple
        $crate::define_config!(@gen_args_struct
            $args_name, $group, $arg_id_prefix
            {
                $(
                    ($field, $env_field, $cli_name, $prefix, $env_prefix, $field_type, $doc
                        $(, value_name = $value_name)?)
                ),*
            }
        );

        // Default implementation for Config
        $crate::define_config!(@impl_default
            $config_name { $($field: $field_type),* }
        );

        // Serialize / Deserialize / merge / resolve / to_raw_config (same as before)
        $crate::impl_raw_serialize!($config_name { $($field),* });
        $crate::impl_raw_deserialize!($config_name { $($field: $field_type),* });
        $crate::impl_merge!($config_name { $($field),* });
        $crate::impl_resolve!($config_name { $($field => $default),* });
        $crate::impl_to_raw_config!($args_name => $config_name { $($field),* });
    };

    // Helper: implement Default with proper where clauses
    (@impl_default
        $config_name:ident { $($field:ident: $field_type:ty),* }
    ) => {
        impl<State: $crate::config::state::ConfigState> Default for $config_name<State>
        where
            $(
                $crate::config::state::Field<State, $field_type>: Default,
            )*
        {
            fn default() -> Self {
                Self {
                    $(
                        $field: $crate::config::state::Field::<State, $field_type>::default(),
                    )*
                    _state: $crate::config::state::StateMarker::new(),
                }
            }
        }
    };

    // Helper: generate Args struct for non-prefixed configs (like SecurityConfig)
    (@gen_args_struct_no_prefix
        $args_name:ident, $group:literal, "", $env_prefix:literal
        {
            $(
                ($field:ident, $env_field:literal, $cli_name:literal, $field_type:ty, $doc:literal
                    $(, value_name = $value_name:literal)?)
            ),*
        }
    ) => {
        #[derive(clap::Args, Debug, Default)]
        #[group(id = $group)]
        pub struct $args_name {
            $(
                #[doc = $doc]
                #[arg(
                    long = $cli_name,
                    env = $crate::define_config!(@env_var $env_prefix, $env_field),
                    help = $doc,
                    $( value_name = $value_name )?
                )]
                pub $field: Option<$field_type>,
            )*
        }
    };

    // Helper: generate Args struct without arg IDs (for non-prefixed configs)
    (@gen_args_struct
        $args_name:ident, $group:literal, ""
        {
            $(
                ($field:ident, $env_field:literal, $cli_name:literal, $prefix:literal, $env_prefix:literal, $field_type:ty, $doc:literal
                    $(, value_name = $value_name:literal)?)
            ),*
        }
    ) => {
        #[derive(clap::Args, Debug, Default)]
        #[group(id = $group)]
        pub struct $args_name {
            $(
                #[doc = $doc]
                #[arg(
                    long = $crate::define_config!(@concat_prefix $prefix, $cli_name),
                    env = $crate::define_config!(@env_var $env_prefix, $env_field),
                    help = $doc,
                    $( value_name = $value_name )?
                )]
                pub $field: Option<$field_type>,
            )*
        }
    };

    // Helper: generate Args struct with arg IDs (for prefixed configs)
    (@gen_args_struct
        $args_name:ident, $group:literal, $arg_id_prefix:literal
        {
            $(
                ($field:ident, $env_field:literal, $cli_name:literal, $prefix:literal, $env_prefix:literal, $field_type:ty, $doc:literal
                    $(, value_name = $value_name:literal)?)
            ),*
        }
    ) => {
        #[derive(clap::Args, Debug, Default)]
        #[group(id = $group)]
        pub struct $args_name {
            $(
                #[doc = $doc]
                #[arg(
                    long = $crate::define_config!(@concat_prefix $prefix, $cli_name),
                    env = $crate::define_config!(@env_var $env_prefix, $env_field),
                    id = $crate::define_config!(@arg_id $arg_id_prefix, $field),
                    help = $doc,
                    $( value_name = $value_name )?
                )]
                pub $field: Option<$field_type>,
            )*
        }
    };

    // Helper: concatenate prefix and cli name
    (@concat_prefix "", $cli_name:literal) => { $cli_name };
    (@concat_prefix $prefix:literal, $cli_name:literal) => {
        concat!($prefix, "-", $cli_name)
    };

    // Helper: generate env var name
    (@env_var "", $env_field:literal) => {
        concat!("PASSLESS_", $env_field)
    };
    (@env_var $env_prefix:literal, $env_field:literal) => {
        concat!("PASSLESS_", $env_prefix, "_", $env_field)
    };

    // Helper: generate arg ID (prefix.field)
    (@arg_id "", $field:ident) => { compile_error!("No arg_id for non-prefixed configs") };
    (@arg_id $prefix:literal, $field:ident) => {
        concat!($prefix, ".", stringify!($field))
    };
}

/// Macro to implement Serialize for Raw config structs
///
/// This generates a manual Serialize implementation that serializes Option<T> fields
#[macro_export]
macro_rules! impl_raw_serialize {
    ($type_name:ident { $($field:ident),+ $(,)? }) => {
        impl serde::Serialize for $type_name<$crate::config::state::Raw> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeStruct;
                let field_count = [ $( stringify!($field) ),+ ].len();
                let mut state = serializer.serialize_struct(stringify!($type_name), field_count)?;
                $(
                    state.serialize_field(stringify!($field), &self.$field)?;
                )+
                state.end()
            }
        }
    };
}

/// Macro to implement Deserialize for Raw config structs
///
/// This generates a manual Deserialize implementation using a helper struct
#[macro_export]
macro_rules! impl_raw_deserialize {
    ($type_name:ident { $($field:ident: $field_type:ty),+ $(,)? }) => {
        impl<'de> serde::Deserialize<'de> for $type_name<$crate::config::state::Raw> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(serde::Deserialize)]
                struct Helper {
                    $(
                        #[serde(default)]
                        $field: Option<$field_type>,
                    )+
                }

                let helper = Helper::deserialize(deserializer)?;
                Ok($type_name {
                    $(
                        $field: helper.$field,
                    )+
                    _state: $crate::config::state::StateMarker::new(),
                })
            }
        }
    };
}

/// Macro to implement merge() for Raw config structs
///
/// Generates a merge method that prefers override values
#[macro_export]
macro_rules! impl_merge {
    ($type_name:ident { $($field:ident),+ $(,)? }) => {
        impl $type_name<$crate::config::state::Raw> {
            /// Merge with another raw config, preferring override values
            pub fn merge(self, other: Self) -> Self {
                Self {
                    $(
                        $field: other.$field.or(self.$field),
                    )+
                    _state: $crate::config::state::StateMarker::new(),
                }
            }
        }
    };
}

/// Macro to implement resolve() for config structs
///
/// Generates a resolve method that applies defaults
#[macro_export]
macro_rules! impl_resolve {
    ($type_name:ident { $($field:ident => $default_expr:expr),+ $(,)? }) => {
        impl $type_name<$crate::config::state::Raw> {
            /// Resolve to a concrete config with defaults applied
            pub fn resolve(self) -> $type_name<$crate::config::state::Resolved> {
                $type_name {
                    $(
                        $field: self.$field.unwrap_or_else(|| $default_expr),
                    )+
                    _state: $crate::config::state::StateMarker::new(),
                }
            }
        }
    };
}

/// Macro to implement to_raw_config() for *ConfigArgs structs
///
/// Converts CLI args to Raw config
#[macro_export]
macro_rules! impl_to_raw_config {
    ($args_type:ident => $config_type:ident { $($field:ident),+ $(,)? }) => {
        impl $args_type {
            pub fn to_raw_config(&self) -> $config_type<$crate::config::state::Raw> {
                $config_type {
                    $(
                        $field: self.$field.clone(),
                    )+
                    _state: $crate::config::state::StateMarker::new(),
                }
            }
        }
    };
}

/// Combined macro for simple config structs (no custom logic)
///
/// This generates all boilerplate for a simple config struct:
/// - Serialize/Deserialize for Raw
/// - merge()
/// - resolve()
/// - to_raw_config() for Args
#[macro_export]
macro_rules! simple_config {
    (
        struct $type_name:ident {
            $(
                $field:ident: $field_type:ty => $default_expr:expr
            ),+ $(,)?
        }
        args $args_type:ident
    ) => {
        $crate::impl_raw_serialize!($type_name { $($field),+ });
        $crate::impl_raw_deserialize!($type_name { $($field: $field_type),+ });
        $crate::impl_merge!($type_name { $($field),+ });
        $crate::impl_resolve!($type_name { $($field => $default_expr),+ });
        $crate::impl_to_raw_config!($args_type => $type_name { $($field),+ });
    };
}
