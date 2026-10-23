package portfolio.jar;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import java.io.*;

public final class ArchiveAuditTests {
    static int passed, failed;
    @FunctionalInterface interface Checked { void run() throws Exception; }
    static void test(String name, Checked body) { try { body.run(); passed++; System.out.println("PASS " + name); } catch (Exception | AssertionError e) { failed++; System.out.println("FAIL " + name + ": " + e); } }
    static void check(boolean value) { if (!value) throw new AssertionError(); }
    static byte[] clazz(int major) { return new byte[] {(byte)0xca,(byte)0xfe,(byte)0xba,(byte)0xbe,0,0,(byte)(major >> 8),(byte)major}; }
    static Path archive(Path folder, Map<String,byte[]> files) throws IOException {
        Path path = folder.resolve(UUID.randomUUID() + ".jar");
        try (var zip = new ZipOutputStream(Files.newOutputStream(path))) {
            for (var entry : files.entrySet()) { zip.putNextEntry(new ZipEntry(entry.getKey())); zip.write(entry.getValue()); zip.closeEntry(); }
        } return path;
    }
    static boolean has(ArchiveAudit.Result result, String rule) { return result.findings().stream().anyMatch(f -> f.rule().equals(rule)); }
    public static void main(String[] args) throws Exception {
        Path folder = Files.createTempDirectory("jar-surface-tests");
        try {
            test("minimal class inspected without execution", () -> { var r = ArchiveAudit.inspect(archive(folder, Map.of("Safe.class", clazz(65))), 21); check(r.baseClasses() == 1 && r.findings().isEmpty()); });
            test("newer base class is a compatibility observation", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("New.class", clazz(69))), 21), "BASE_CLASS_RUNTIME")));
            test("traversal names are detected, never extracted", () -> { var p = archive(folder, Map.of("../escape.txt", new byte[] {1})); check(has(ArchiveAudit.inspect(p, 21), "UNSAFE_ENTRY_PATH")); check(!Files.exists(folder.getParent().resolve("escape.txt"))); });
            test("windows backslash traversal", () -> check(ArchiveAudit.unsafeName("dir\\..\\x")));
            test("absolute drive path", () -> check(ArchiveAudit.unsafeName("C:\\x")));
            test("harmless double dots inside filename", () -> check(!ArchiveAudit.unsafeName("x..y.class")));
            test("case collisions preserved", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("A.class", clazz(65), "a.class", clazz(65))), 21), "NAME_COLLISION")));
            test("signature file is not a verified signature", () -> { var r = ArchiveAudit.inspect(archive(folder, Map.of("META-INF/demo.SF", new byte[] {1})), 21); check(r.signatureArtifactsPresent()); check(Reports.json(r).contains("\"signature_verification_performed\":false")); });
            test("nested archive stays an inventory gap", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("lib/nested.jar", new byte[] {1})), 21), "NESTED_ARCHIVE")));
            test("malformed class header", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("x.class", new byte[] {1})), 21), "INVALID_CLASS_HEADER")));
            test("remote manifest classpath", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nClass-Path: https://example.invalid/a.jar\r\n\r\n".getBytes())), 21), "EXTERNAL_CLASSPATH")));
            test("multi-release classes do not raise base version", () -> { var r = ArchiveAudit.inspect(archive(folder, Map.of("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n".getBytes(), "META-INF/versions/25/Version.class", clazz(69))), 21); check(r.highestBaseJava() == 0 && r.multiRelease() && !has(r, "BASE_CLASS_RUNTIME")); });
            test("undeclared multi-release directory", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("META-INF/versions/25/V.class", clazz(69))), 21), "UNDECLARED_VERSIONED_CLASS")));
            test("compression expansion warning", () -> check(has(ArchiveAudit.inspect(archive(folder, Map.of("synthetic-zeroes.bin", new byte[1_100_000])), 21), "EXPANSION_RISK")));
            test("oversized manifest rejected", () -> { try { ArchiveAudit.inspect(archive(folder, Map.of("META-INF/MANIFEST.MF", new byte[65537])), 21); throw new AssertionError(); } catch (IOException expected) { } });
            test("malformed ZIP rejected", () -> { Path p = folder.resolve("bad.jar"); Files.writeString(p, "not zip"); check(Main.run(new String[] {p.toString(), folder.resolve("out").toString()}) == 2); });
            test("JSON escapes controls and quotes", () -> check(Reports.quote("a\n\"b\\").equals("\"a\\n\\\"b\\\\\"")));
            test("input hash stable and report generated", () -> { Path p = archive(folder, Map.of("x.txt", new byte[] {1})); var a = ArchiveAudit.inspect(p, 21); check(a.sha256().equals(ArchiveAudit.inspect(p, 21).sha256())); check(Main.run(new String[] {p.toString(), folder.resolve("out").toString()}) == 0); check(Files.exists(folder.resolve("out/archive.json"))); });
        } finally { try (var paths = Files.walk(folder)) { for (var p : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(p); } }
        System.out.println(passed + "/" + (passed + failed) + " passed"); if (failed != 0) System.exit(1);
    }
}
