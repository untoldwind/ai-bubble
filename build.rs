//! Build-time JSON-schema generation for the sandbox spec file.
//!
//! The build script compiles `src/spec/mod.rs` itself (with stand-ins for the
//! pieces the main crate provides, like `crate::sandbox::die`) and uses
//! `schemars` to derive a JSON Schema for `Spec`, honoring the serde
//! attributes. The result is written to `OUT_DIR/ai-bubble-schema.json`,
//! which the main crate embeds as `spec::SPEC_SCHEMA` and prints with
//! `--print-schema`. Point a spec file's editor at it (e.g. VS Code's
//! `json.schemas`, or `"$schema"` once the schema lives somewhere the
//! editor can find) to get completion and validation for
//! `.ai-bubble/spec.json`.
//!
//! Because the schema is generated from the very same source files that
//! do the deserialization, it can never drift from what the program
//! actually accepts (the hand-written `TmpfsPerms` deserializer is
//! described manually in `spec/tmpfs.rs`).

mod sandbox {
    /// Stand-in for the main crate's `sandbox::die`: the schema generation
    /// never loads a spec file, so this is only here to satisfy the
    /// `crate::sandbox::die` references inside `spec.rs`.
    pub fn die(msg: &str) -> ! {
        panic!("{msg}")
    }
}

#[path = "src/spec/mod.rs"]
#[allow(dead_code)] // the main crate uses these; the schema generation only needs the types
mod spec;

fn main() {
    println!("cargo:rerun-if-changed=src/spec/mod.rs");
    println!("cargo:rerun-if-changed=src/spec/file.rs");
    println!("cargo:rerun-if-changed=src/spec/audit.rs");
    println!("cargo:rerun-if-changed=src/spec/env.rs");
    println!("cargo:rerun-if-changed=src/spec/internal.rs");
    println!("cargo:rerun-if-changed=src/spec/tmpfs.rs");
    println!("cargo:rerun-if-changed=src/spec/net.rs");
    println!("cargo:rerun-if-changed=src/spec/hostfs.rs");

    let mut schema = schemars::r#gen::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<spec::Spec>();
    schema
        .schema
        .metadata
        .as_mut()
        .expect("root schema has metadata")
        .title = Some("ai-bubble sandbox spec".to_string());

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is set for build scripts");
    let path = std::path::Path::new(&out_dir).join("ai-bubble-schema.json");
    let json = serde_json::to_string_pretty(&schema).expect("schema serializes");
    std::fs::write(&path, json + "\n").expect("can write into OUT_DIR");
}
