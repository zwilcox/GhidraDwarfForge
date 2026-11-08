// Apply source-built fixture function identities and extents as analyst curation.
// No unwind rules, saved registers or frame locations are supplied to Ghidra.
// @category DWARF.Tests

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareCfiFixture extends GhidraScript {
    @Override
    protected void run() throws Exception {
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        for (String line : Files.readAllLines(Path.of(getScriptArgs()[0]))) {
            monitor.checkCancelled();
            String[] fields = line.split(" ");
            if (fields.length != 3 || !fields[0].matches("cfi_(checkpoint|recursive|outer|main)")) {
                throw new IllegalArgumentException("unexpected CFI fixture identity: " + line);
            }
            long value = Long.parseUnsignedLong(fields[1], 16);
            long size = Long.parseLong(fields[2]);
            if (size <= 0 || size > 4096) {
                throw new IllegalArgumentException("unbounded CFI fixture function");
            }
            var entry = toAddr(Math.addExact(value, delta));
            var end = entry.addNoWrap(size - 1);
            var body = new AddressSet(entry, end);
            // Ghidra's AArch64 --emit-relocs import may split a compiler symbol
            // at an interior call. This test explicitly curates the known body.
            var interior = new ArrayList<Function>();
            var functions = currentProgram.getFunctionManager().getFunctions(body, true);
            while (functions.hasNext()) {
                var function = functions.next();
                if (!function.getEntryPoint().equals(entry)) interior.add(function);
            }
            for (var function : interior) {
                currentProgram.getFunctionManager().removeFunction(function.getEntryPoint());
            }
            var function = getFunctionAt(entry);
            if (function == null) {
                disassemble(entry);
                function = createFunction(entry, fields[0]);
            }
            if (function == null) throw new IllegalStateException("missing fixture entry " + entry);
            function.setBody(body);
            function.setName(fields[0], SourceType.USER_DEFINED);
            println("CFI_FIXTURE " + fields[0] + " " + entry + ".." + end);
        }
    }
}
