import com.zerodayguardian.detector.detection.ContainerEscapeRules;
import com.zerodayguardian.detector.event.SyscallEvent;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

public class EduFlowReplay {
    public static void main(String[] args) throws Exception {
        var records = ByteBuffer.wrap(Files.readAllBytes(Path.of(args[0])));
        if (records.remaining() != 2 * SyscallEvent.SERIALIZED_SIZE) {
            throw new IllegalArgumentException("Expected exactly two event records");
        }

        var rules = new ContainerEscapeRules();
        var normal = rules.analyze(SyscallEvent.decode(records));
        var alert = rules.analyze(SyscallEvent.decode(records));
        if (normal.detected() || !alert.detected()
                || !"CRITICAL".equals(alert.severity().name())
                || !"T1611".equals(alert.mitreAttackId())) {
            throw new IllegalStateException("Unexpected detection result: " + normal + " / " + alert);
        }

        System.out.println("[2/3] Decoded two 384-byte records with Guardian's Java decoder");
        System.out.println("      Baseline fixture: no alert");
        System.out.printf(Locale.ROOT,
                "      Synthetic fixture: %s / %s / %s / rule score %.2f%n",
                alert.severity(), alert.category(), alert.mitreAttackId(), alert.score());
        System.out.println("[3/3] PASS: replay completed without Kubernetes writes");
    }
}
