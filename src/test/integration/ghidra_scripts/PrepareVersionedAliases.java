// @category DWARF.Tests
import java.nio.file.Files;
import java.nio.file.Path;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraImageBase;

public class PrepareVersionedAliases extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || !java.util.List.of("curate", "observe").contains(args[0])) {
            throw new IllegalArgumentException("<curate|observe> <records.tsv>");
        }
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        int count = 0;
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            monitor.checkCancelled();
            String[] fields = line.split("\\t");
            if (fields.length != 4) throw new AssertionError("invalid compiler record");
            var entry = toAddr(Math.addExact(Long.parseLong(fields[1]), delta));
            long size = Long.parseLong(fields[2]);
            String original = fields[0].substring("recovered::alternate_".length());
            var function = getFunctionAt(entry);
            if (function == null || function.getBody().getNumAddressRanges() != 1 ||
                    !function.getBody().getMinAddress().equals(entry) ||
                    function.getBody().getNumAddresses() != size) {
                throw new AssertionError("compiler/function body disagreement");
            }
            var table = currentProgram.getSymbolTable();
            if (args[0].equals("curate")) {
                var owner = table.getOrCreateNameSpace(currentProgram.getGlobalNamespace(),
                    "recovered", SourceType.USER_DEFINED);
                function.setParentNamespace(owner);
                function.setName("analyst_" + original, SourceType.USER_DEFINED);
                function.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
                    new ReturnParameterImpl(IntegerDataType.dataType, currentProgram),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", IntegerDataType.dataType, currentProgram));
                table.createLabel(entry, "alternate_" + original, owner, SourceType.USER_DEFINED);
            }
            var alias = table.getSymbol("alternate_" + original, entry, function.getParentNamespace());
            if (!function.getName(true).equals("recovered::analyst_" + original) ||
                    function.getSignatureSource() != SourceType.USER_DEFINED ||
                    function.getParameterCount() != 1 || !function.getParameter(0).getName().equals("value") ||
                    function.getReturnType().getLength() != 4 || alias == null || alias.isPrimary() ||
                    alias.getSource() != SourceType.USER_DEFINED || !alias.getName(true).equals(fields[0])) {
                throw new AssertionError("curated versioned alias did not persist");
            }
            count++;
        }
        if (count != 2) throw new AssertionError("expected two curated definitions");
        println("versioned-alias-curation=PASS");
    }
}
