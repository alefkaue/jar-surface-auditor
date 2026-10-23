package portfolio.jar;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.jar.Manifest;
import java.util.zip.*;

/** Static bounded archive inspection; never loads classes or extracts entries. */
public final class ArchiveAudit {
    public record Finding(String rule, String priority, String entry, String evidence, String recommendation) {}
    public record Result(String sha256, int entries, int baseClasses, int highestBaseJava,
                         int targetJava, boolean signatureArtifactsPresent, boolean multiRelease,
                         List<Finding> findings) {}
    private ArchiveAudit() {}

    public static boolean unsafeName(String name) {
        String normalized = name.replace('\\', '/');
        return normalized.startsWith("/") || normalized.matches("^[a-zA-Z]:.*")
            || Arrays.asList(normalized.split("/", -1)).contains("..");
    }

    public static Result inspect(Path path, int targetJava) throws IOException {
        if (targetJava < 8 || targetJava > 50) throw new IllegalArgumentException("target Java must be 8..50");
        if (Files.size(path) > 50_000_000) throw new IOException("Archive exceeds 50 MB");
        List<Finding> findings = new ArrayList<>();
        int count = 0, baseClasses = 0, highestJava = 0;
        boolean signatures = false, multiRelease = false;
        Set<String> names = new HashSet<>();
        Map<String,String> normalizedNames = new HashMap<>();
        try (ZipFile archive = new ZipFile(path.toFile())) {
            if (archive.size() > 10000) throw new IOException("Archive exceeds 10000 entries");
            ZipEntry manifestEntry = archive.getEntry("META-INF/MANIFEST.MF");
            if (manifestEntry != null) {
                try (InputStream stream = archive.getInputStream(manifestEntry)) {
                    byte[] bytes = stream.readNBytes(65537);
                    if (bytes.length > 65536) throw new IOException("Manifest exceeds 64 KiB");
                    Manifest manifest = new Manifest(new ByteArrayInputStream(bytes));
                    var attrs = manifest.getMainAttributes();
                    multiRelease = "true".equalsIgnoreCase(attrs.getValue("Multi-Release"));
                    String classpath = attrs.getValue("Class-Path");
                    if (classpath != null && Arrays.stream(classpath.split("\\s+")).anyMatch(value ->
                            value.contains(":") || value.startsWith("/") || unsafeName(value)))
                        findings.add(new Finding("EXTERNAL_CLASSPATH", "medium", manifestEntry.getName(),
                            "Manifest references a scheme, absolute location or parent traversal.",
                            "Review deployment classpath resolution; a manifest reference is not proof that code was downloaded or executed."));
                }
            }
            var entries = archive.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement(); count++;
                String name = entry.getName();
                if (!names.add(name)) findings.add(new Finding("DUPLICATE_ENTRY", "medium", name,
                    "The same archive name appears more than once.", "Resolve ambiguous resource/class selection before deployment."));
                String normalized = name.replace('\\', '/').toLowerCase(Locale.ROOT);
                String earlier = normalizedNames.putIfAbsent(normalized, name);
                if (earlier != null && !earlier.equals(name)) findings.add(new Finding("NAME_COLLISION", "medium", name,
                    "Case/separator-normalized name collides with " + earlier,
                    "Review cross-platform extraction/loading behavior; this tool extracts nothing."));
                if (unsafeName(name)) findings.add(new Finding("UNSAFE_ENTRY_PATH", "high", name,
                    "Entry is absolute or contains a parent-directory segment.",
                    "Reject unsafe entry names before any extraction; inspect build provenance."));
                if (normalized.startsWith("meta-inf/") && normalized.matches(".*\\.(sf|rsa|dsa|ec)$")) signatures = true;
                if (entry.isDirectory()) continue;
                long size = entry.getSize(), compressed = entry.getCompressedSize();
                if (size > 32_000_000 || size > 1_000_000 && compressed >= 0 && size / Math.max(1, compressed) > 200)
                    findings.add(new Finding("EXPANSION_RISK", "medium", name,
                        "Large declared expansion size or compression ratio.", "Inspect with resource limits. Metadata alone does not prove a zip bomb."));
                if (normalized.endsWith(".jar")) findings.add(new Finding("NESTED_ARCHIVE", "review", name,
                    "Nested JAR was inventoried but not recursively inspected.", "Inventory dependencies separately; do not infer nested code is safe."));
                if (normalized.endsWith(".class") && size <= 32_000_000) {
                    try (InputStream stream = archive.getInputStream(entry)) {
                        byte[] header = stream.readNBytes(8);
                        if (header.length < 8 || (header[0] & 255) != 0xca || (header[1] & 255) != 0xfe
                                || (header[2] & 255) != 0xba || (header[3] & 255) != 0xbe) {
                            findings.add(new Finding("INVALID_CLASS_HEADER", "medium", name,
                                "A .class entry lacks the expected eight-byte header.", "Review malformed or mislabeled build artifacts."));
                            continue;
                        }
                        int major = (header[6] & 255) * 256 + (header[7] & 255);
                        int javaVersion = major - 44;
                        boolean versioned = normalized.startsWith("meta-inf/versions/");
                        if (!versioned) {
                            baseClasses++;
                            highestJava = Math.max(highestJava, javaVersion);
                            if (javaVersion > targetJava) findings.add(new Finding("BASE_CLASS_RUNTIME", "medium", name,
                                "Base class major " + major + " indicates Java " + javaVersion + ", target is " + targetJava + ".",
                                "Verify intended runtime and build target; this is a compatibility finding, not a CVE."));
                        } else if (!multiRelease) findings.add(new Finding("UNDECLARED_VERSIONED_CLASS", "review", name,
                            "Versioned class exists without Multi-Release: true.", "Review packaging intent; versioned entries were not treated as base-runtime requirements."));
                    }
                }
            }
        }
        return new Result(sha256(path), count, baseClasses, highestJava, targetJava, signatures, multiRelease, List.copyOf(findings));
    }

    static String sha256(Path path) throws IOException {
        try (InputStream stream = Files.newInputStream(path)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] chunk = new byte[8192]; int n;
            while ((n = stream.read(chunk)) != -1) digest.update(chunk, 0, n);
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
