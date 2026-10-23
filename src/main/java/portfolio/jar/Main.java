package portfolio.jar;
import java.io.IOException;
import java.nio.file.*;

public final class Main {
    private Main() {}
    public static int run(String[] args) {
        if (args.length == 1 && args[0].equals("--help")) {
            System.out.println("jar-surface-auditor INPUT.jar OUTPUT_DIRECTORY [TARGET_JAVA]\nStatic offline analysis; default target Java 21."); return 0;
        }
        if (args.length < 2 || args.length > 3) return 2;
        try {
            int target = args.length == 3 ? Integer.parseInt(args[2]) : 21;
            var result = ArchiveAudit.inspect(Path.of(args[0]), target);
            var out = Path.of(args[1]); Files.createDirectories(out);
            Files.writeString(out.resolve("archive.json"), Reports.json(result));
            Files.writeString(out.resolve("archive.md"), Reports.markdown(result));
            System.out.println("Entries: " + result.entries() + "; findings for review: " + result.findings().size());
            return 0;
        } catch (IOException | IllegalArgumentException e) {
            System.err.println("Input/report error: " + e.getMessage()); return 2;
        }
    }
    public static void main(String[] args) { System.exit(run(args)); }
}
