package com.zerodayguardian.detector.event;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SyscallEventTest {

    @Test
    void decodeShouldParseValidEvent() {
        ByteBuffer buf = createTestEvent(
                SyscallEvent.MAGIC,
                SyscallEvent.CURRENT_VERSION,
                1, // EXECVE
                SyscallEvent.FLAG_FROM_CONTAINER | SyscallEvent.FLAG_SUSPICIOUS,
                1_000_000_000L,
                1234, 1234, 1000, 1000,
                "bash",
                "/bin/bash",
                42L,
                "abc123def456");

        SyscallEvent event = SyscallEvent.decode(buf);

        assertEquals(SyscallEvent.MAGIC, event.magic());
        assertEquals(EventType.EXECVE, event.eventType());
        assertTrue(event.isFromContainer());
        assertTrue(event.isSuspicious());
        assertFalse(event.isPrivileged());
        assertEquals(1234, event.pid());
        assertEquals(1000, event.uid());
        assertEquals("bash", event.comm());
        assertEquals("/bin/bash", event.filename());
        assertEquals(42L, event.cgroupId());
        assertEquals("abc123def456", event.containerId());
        assertTrue(event.hasContainerId());
    }

    @Test
    void decodeShouldRejectInvalidMagic() {
        ByteBuffer buf = createTestEvent(0xBADBAD, 1, 1, 0, 0L, 0, 0, 0, 0, "", "", 0L, "");
        assertThrows(IllegalArgumentException.class, () -> SyscallEvent.decode(buf));
    }

    @Test
    void decodeShouldRejectUnsupportedVersion() {
        ByteBuffer buf = createTestEvent(SyscallEvent.MAGIC, 99, 1, 0, 0L, 0, 0, 0, 0, "", "", 0L, "");
        assertThrows(IllegalArgumentException.class, () -> SyscallEvent.decode(buf));
    }

    @Test
    void timestampShouldConvertCorrectly() {
        ByteBuffer buf = createTestEvent(
                SyscallEvent.MAGIC, 1, 1, 0,
                1_500_000_000_000_000_000L,
                0, 0, 0, 0, "", "", 0L, "");

        SyscallEvent event = SyscallEvent.decode(buf);
        assertEquals(1_500_000_000L, event.timestamp().getEpochSecond());
        assertEquals(0L, event.timestamp().getNano());
    }

    @Test
    void flagsShouldDecodeCorrectly() {
        ByteBuffer buf = createTestEvent(
                SyscallEvent.MAGIC, 1, 1,
                SyscallEvent.FLAG_PRIVILEGED_CTX | SyscallEvent.FLAG_HOST_NAMESPACE,
                0L, 0, 0, 0, 0, "", "", 0L, "");

        SyscallEvent event = SyscallEvent.decode(buf);
        assertFalse(event.isFromContainer());
        assertTrue(event.isPrivileged());
        assertTrue(event.isHostNamespace());
        assertFalse(event.isSuspicious());
    }

    private static ByteBuffer createTestEvent(
            int magic, int version, int eventType, int flags,
            long timestampNs, int pid, int tgid, int uid, int gid,
            String comm, String filename, long cgroupId, String containerId) {

        ByteBuffer buf = ByteBuffer.allocate(SyscallEvent.SERIALIZED_SIZE);
        buf.order(ByteOrder.LITTLE_ENDIAN);

        buf.putInt(magic);
        buf.putInt(version);
        buf.putInt(eventType);
        buf.putInt(flags);
        buf.putLong(timestampNs);
        buf.putInt(pid);
        buf.putInt(tgid);
        buf.putInt(uid);
        buf.putInt(gid);

        putFixedString(buf, comm, 16);
        putFixedString(buf, filename, 256);
        buf.putLong(cgroupId);
        putFixedString(buf, containerId, 64);

        buf.flip();
        return buf;
    }

    private static void putFixedString(ByteBuffer buf, String value, int fieldWidth) {
        byte[] bytes = value != null ? value.getBytes(StandardCharsets.UTF_8) : new byte[0];
        int len = Math.min(bytes.length, fieldWidth);
        buf.put(bytes, 0, len);
        for (int i = len; i < fieldWidth; i++) {
            buf.put((byte) 0);
        }
    }
}
