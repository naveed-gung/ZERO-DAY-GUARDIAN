use aya_build::cargo_metadata;

fn main() {
    // Build the eBPF crate for the BPF target.
    // aya-build resolves the ebpf-monitor-ebpf crate from the workspace
    // and compiles it with the bpf-linker for the bpfel-unknown-none target.
    let metadata = cargo_metadata().expect("Failed to read cargo metadata");
    let ebpf_package = metadata
        .packages
        .iter()
        .find(|p| p.name == "ebpf-monitor-ebpf")
        .expect("ebpf-monitor-ebpf package not found in workspace");

    aya_build::build_ebpf([ebpf_package.clone()]).expect("Failed to build eBPF programs");
}
