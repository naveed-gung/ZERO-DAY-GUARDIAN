use aya_build::{build_ebpf, Package, Toolchain};

fn main() {
    // Build the eBPF crate for the BPF target.
    // aya-build compiles ebpf-monitor-ebpf with -Z build-std=core
    // targeting bpfel-unknown-none via bpf-linker.
    build_ebpf(
        [Package {
            name: "ebpf-monitor-ebpf",
            root_dir: "../ebpf-monitor-ebpf",
            ..Default::default()
        }],
        Toolchain::default(),
    )
    .expect("Failed to build eBPF programs");
}
