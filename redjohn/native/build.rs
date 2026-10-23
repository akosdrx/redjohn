fn main() {
    // The cdylib must resolve Python symbols from the loading interpreter,
    // never from a concrete libpython baked in at build time. pyo3 emits
    // these flags through its own build chain when the extension-module
    // feature is enabled; emitting them here as well makes the artifact
    // correct independent of that plumbing.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-undefined");
        println!("cargo:rustc-cdylib-link-arg=dynamic_lookup");
    }
}
