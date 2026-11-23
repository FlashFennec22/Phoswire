fn main() {
    // The tray window needs version 6 of the common controls, for visual
    // styles and collapsible list groups; without this manifest Windows loads
    // version 5. Only the MSVC linker understands these options.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bin=phoswire-tray=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin=phoswire-tray=/MANIFESTDEPENDENCY:type='win32' \
             name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' \
             publicKeyToken='6595b64144ccf1df' language='*'"
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
