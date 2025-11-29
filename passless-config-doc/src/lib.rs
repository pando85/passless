use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Expr, Fields, Lit, Meta, Type, parse_macro_input};

/// Extract doc comments from attributes
fn extract_doc(attrs: &[syn::Attribute]) -> String {
    attrs
        .iter()
        .filter_map(|attr| {
            if attr.path().is_ident("doc")
                && let Meta::NameValue(nv) = &attr.meta
                && let Expr::Lit(expr_lit) = &nv.value
                && let Lit::Str(lit_str) = &expr_lit.lit
            {
                return Some(lit_str.value().trim().to_string());
            }
            None
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Get the type name from a Type
fn get_type_name(ty: &Type) -> Option<String> {
    if let Type::Path(type_path) = ty
        && let Some(segment) = type_path.path.segments.last()
    {
        return Some(segment.ident.to_string());
    }
    None
}

/// Check if a type is a config struct (ends with "Config")
fn is_config_type(ty: &Type) -> bool {
    get_type_name(ty)
        .map(|name| name.ends_with("Config"))
        .unwrap_or(false)
}

/// Derive macro to extract doc comments and generate TOML config with comments
///
/// This macro generates `field_docs()` and for AppConfig, also generates
/// `to_toml_with_comments()` that creates a fully documented TOML config.
///
/// Documentation is extracted from:
/// - Struct-level doc comments (for section headers)
/// - Field-level doc comments (for field descriptions)
#[proc_macro_derive(ConfigDoc, attributes(config_example))]
pub fn derive_config_doc(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let struct_doc = extract_doc(&input.attrs);

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("ConfigDoc only supports structs with named fields"),
        },
        _ => panic!("ConfigDoc only supports structs"),
    };

    let mut field_info = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let doc = extract_doc(&field.attrs);
        let type_name = get_type_name(&field.ty);
        let is_config = is_config_type(&field.ty);

        field_info.push((field_name.clone(), doc, is_config, type_name));
    }

    let field_names: Vec<_> = field_info
        .iter()
        .map(|(n, _, _, _)| n.to_string())
        .collect();
    let field_help: Vec<_> = field_info.iter().map(|(_, d, _, _)| d).collect();

    // Build field access expressions for to_toml_fields
    let field_accessors: Vec<_> = field_info
        .iter()
        .filter(|(_, _, is_config, _)| !is_config)
        .map(|(field_name, _, _, _)| {
            quote! {
                (stringify!(#field_name), format!("{:?}", self.#field_name))
            }
        })
        .collect();

    let mut expanded = quote! {
        impl #name {
            /// Get documentation for all fields
            /// Returns an array of (field_name, documentation) tuples
            pub fn field_docs() -> &'static [(&'static str, &'static str)] {
                &[
                    #((#field_names, #field_help),)*
                ]
            }

            /// Get struct-level documentation
            pub fn struct_doc() -> &'static str {
                #struct_doc
            }

            /// Get field values as TOML-formatted strings
            pub fn to_toml_fields(&self) -> Vec<(&'static str, String)> {
                vec![
                    #(#field_accessors),*
                ]
            }
        }
    };

    // If this is AppConfig, generate to_toml_with_comments
    if name == "AppConfig" {
        let toml_gen = generate_toml_method(&field_info);
        expanded = quote! {
            #expanded
            #toml_gen
        };
    }

    TokenStream::from(expanded)
}

/// Generate the to_toml_with_comments method for AppConfig
#[allow(clippy::type_complexity)]
fn generate_toml_method(
    fields: &[(syn::Ident, String, bool, Option<String>)],
) -> proc_macro2::TokenStream {
    let mut output_parts = Vec::new();

    // Header
    output_parts.push(quote! {
        output.push_str("# Passless Configuration File Example\n");
        output.push_str("# Place this file at: ~/.config/passless/config.toml\n\n");
    });

    // Process fields
    for (field_name, doc, is_config, type_name) in fields {
        let field_name_str = field_name.to_string();

        if !is_config {
            // Simple field - add to root section
            if !doc.is_empty() {
                output_parts.push(quote! {
                    output.push_str(&format!("# {}\n", #doc));
                });
            }

            // Output the value
            output_parts.push(quote! {
                output.push_str(&format!("{} = {:?}\n\n", #field_name_str, self.#field_name));
            });
        } else if let Some(type_name) = type_name {
            // Config struct - generate section dynamically
            let type_ident = syn::Ident::new(type_name, proc_macro2::Span::call_site());

            output_parts.push(quote! {
                // Section header with struct doc
                if !#type_ident::struct_doc().is_empty() {
                    output.push_str("# ");
                    output.push_str(#type_ident::struct_doc());
                    output.push_str("\n");
                }

                // TOML section header
                output.push_str(&format!("[{}]\n", #field_name_str));

                // Get field values from the nested struct
                let field_values = self.#field_name.to_toml_fields();

                // Iterate through all fields in the config struct
                for (name, doc) in #type_ident::field_docs() {
                    // Field documentation
                    if !doc.is_empty() {
                        output.push_str(&format!("# {}\n", doc));
                    }


                    // Find the value for this field
                    if let Some((_, value)) = field_values.iter().find(|(n, _)| *n == *name) {
                        output.push_str(&format!("{} = {}\n\n", name, value));
                    }
                }
            });
        }
    }

    quote! {
        impl AppConfig {
            /// Generate TOML configuration with comments extracted from doc comments
            pub fn to_toml_with_comments(&self) -> String {
                let mut output = String::new();
                #(#output_parts)*
                output
            }
        }
    }
}
