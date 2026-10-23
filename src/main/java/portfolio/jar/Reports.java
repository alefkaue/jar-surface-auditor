package portfolio.jar;
import java.util.stream.Collectors;

public final class Reports {
    private Reports() {}
    public static String quote(String value) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t");
                default -> { if (c < 32 || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int)c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }
    public static String json(ArchiveAudit.Result r) {
        String findings = r.findings().stream().map(f -> "{\"rule\":" + quote(f.rule()) +
            ",\"priority\":" + quote(f.priority()) + ",\"entry\":" + quote(f.entry()) +
            ",\"evidence\":" + quote(f.evidence()) + ",\"recommendation\":" + quote(f.recommendation()) + "}").collect(Collectors.joining(",\n"));
        return "{\"schema_version\":1,\"scope\":\"Static metadata review; no classes loaded or entries extracted\",\"sha256\":" + quote(r.sha256()) +
            ",\"entries\":" + r.entries() + ",\"base_classes\":" + r.baseClasses() + ",\"highest_base_java\":" + r.highestBaseJava() +
            ",\"target_java\":" + r.targetJava() + ",\"signature_artifacts_present\":" + r.signatureArtifactsPresent() +
            ",\"signature_verification_performed\":false,\"multi_release\":" + r.multiRelease() + ",\"findings\":[" + findings + "]}\n";
    }
    static String safe(String value) { return value.replace("\r", " ").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;"); }
    public static String markdown(ArchiveAudit.Result r) {
        StringBuilder b = new StringBuilder("# JAR surface audit\n\nStatic analysis, no execution/extraction.\n\nSHA-256: `" + r.sha256() + "`\n\n");
        b.append("Entries: ").append(r.entries()).append("; base classes: ").append(r.baseClasses()).append("; target Java: ").append(r.targetJava()).append(".\n\n");
        b.append("Signature artifacts present: ").append(r.signatureArtifactsPresent()).append(". Signatures were NOT verified.\n");
        for (var f : r.findings()) b.append("\n- **").append(f.priority()).append(" / ").append(f.rule()).append("** — ").append(safe(f.entry())).append(": ").append(safe(f.evidence())).append(" ").append(safe(f.recommendation())).append('\n');
        return b.toString();
    }
}
