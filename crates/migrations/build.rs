//! Rebuilds embedded migrations whenever the released SQL history changes.

fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
