package com.zerodayguardian.detector.event;

/**
 * Event types mirroring the Rust eBPF EventType enum.
 *
 * <p>
 * Wire values must match the u32 discriminant in
 * {@code ebpf-monitor-common/src/lib.rs}.
 * </p>
 *
 * @author Naveed Gung
 */
public enum EventType {

    EXECVE(1, "Process execution"),
    UNSHARE(2, "Namespace manipulation"),
    MOUNT(3, "Filesystem mount"),
    PTRACE(4, "Process trace/debug"),
    NETWORK(5, "Network activity"),
    AUDIT(6, "Kubernetes audit event"),
    INIT_MODULE(7, "Kernel module loading");

    private final int wireValue;
    private final String description;

    EventType(int wireValue, String description) {
        this.wireValue = wireValue;
        this.description = description;
    }

    public int getWireValue() {
        return wireValue;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Decode from the u32 wire representation.
     *
     * @param value wire value from the ring buffer
     * @return the corresponding EventType
     * @throws IllegalArgumentException if the value is unknown
     */
    public static EventType fromWireValue(int value) {
        for (EventType type : values()) {
            if (type.wireValue == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown event type wire value: " + value);
    }
}
