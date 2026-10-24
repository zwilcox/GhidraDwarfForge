// Research-only probe of compiler inline import and Ghidra's separate inline flag.
// @category GhidraDwarfForge.Research

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.symbol.SourceType;

public class InlineEvidenceProbe extends GhidraScript {
    private static final String INLINE_COMMENTS = "DWARF.Add Inlined Functions Comments";
    private static final String LOCAL_VARIABLES = "DWARF.Import Local Variable Info";
    private static final String SOURCE_LINES = "DWARF.Import Source Line Info";

    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length == 1 && arguments[0].equals("configure")) {
            Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
            for (String option : new String[] { INLINE_COMMENTS, LOCAL_VARIABLES, SOURCE_LINES }) {
                require(options.containsKey(option), "missing analysis option: " + option);
                setAnalysisOption(currentProgram, option, "true");
            }
            println("inline-evidence-options=PASS");
            return;
        }
        require(arguments.length == 2, "usage: <output-directory> <debug|no-debug>");
        boolean hasDwarf = arguments[1].equals("debug");
        require(hasDwarf || arguments[1].equals("no-debug"), "invalid probe mode");
        Path output = Path.of(arguments[0]);
        Files.createDirectories(output);
        StringBuilder report = new StringBuilder();
        report.append("mode=").append(arguments[1]).append('\n');
        Function inlineCaller = function("inline_caller");
        Function ordinaryCaller = function("ordinary_caller");
        Function ordinaryCallee = function("ordinary_callee");
        require(getGlobalFunctions("compiler_inline").isEmpty(),
            "compiler inline unexpectedly has an out-of-line function");
        report.append("compiler-inline-listing-functions=0\n");

        int importedInlineLocals = 0;
        for (Function function : new Function[] { inlineCaller, ordinaryCaller, ordinaryCallee }) {
            report.append("function=").append(function.getName())
                .append(" entry=").append(function.getEntryPoint())
                .append(" body=").append(function.getBody())
                .append(" inline-flag=").append(function.isInline()).append('\n');
            for (Variable variable : function.getLocalVariables()) {
                report.append("local parent=").append(function.getName())
                    .append(" name=").append(variable.getName())
                    .append(" first-use=").append(variable.getFirstUseOffset())
                    .append(" storage=").append(variable.getVariableStorage())
                    .append(" source=").append(variable.getSource()).append('\n');
                if (function.equals(inlineCaller) &&
                        variable.getName().startsWith("inline_local") &&
                        variable.getSource() == SourceType.IMPORTED) {
                    importedInlineLocals++;
                }
            }
        }
        report.append("imported-inline-locals-in-parent=")
            .append(importedInlineLocals).append('\n');
        require(hasDwarf ? importedInlineLocals == 2 : importedInlineLocals == 0,
            "unexpected imported inline-local retention");

        int sourceRows = 0;
        for (SourceFile source : currentProgram.getSourceFileManager().getMappedSourceFiles()) {
            for (SourceMapEntry entry : currentProgram.getSourceFileManager()
                    .getSourceMapEntries(source)) {
                if (inlineCaller.getBody().intersects(entry.getBaseAddress(),
                        entry.getBaseAddress().add(Math.max(entry.getLength(), 1) - 1))) {
                    report.append("source-row file=").append(source.getPath())
                        .append(" line=").append(entry.getLineNumber())
                        .append(" base=").append(entry.getBaseAddress())
                        .append(" length=").append(entry.getLength()).append('\n');
                    sourceRows++;
                }
            }
        }
        report.append("inline-caller-source-rows=").append(sourceRows).append('\n');
        int inlineComments = 0;
        AddressIterator addresses = inlineCaller.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address address = addresses.next();
            for (CommentType type : new CommentType[] { CommentType.PRE, CommentType.EOL }) {
                String comment = currentProgram.getListing().getComment(type, address);
                if (comment != null) {
                    report.append("comment address=").append(address)
                        .append(" type=").append(type).append(" text=")
                        .append(comment.replace('\n', '|')).append('\n');
                    if (comment.contains("inline ") && comment.contains("compiler_inline")) {
                        inlineComments++;
                    }
                }
            }
        }
        report.append("compiler-inline-comments=").append(inlineComments).append('\n');
        require(hasDwarf ? sourceRows > 0 : sourceRows == 0,
            "unexpected source-row import result");
        require(hasDwarf ? inlineComments > 0 : inlineComments == 0,
            "unexpected compiler-inline comment result");

        decompile(inlineCaller, null, output.resolve("compiler-inline.c"), report);
        int rawBefore = countRawCalls(ordinaryCaller, ordinaryCallee.getEntryPoint());
        require(rawBefore > 0, "ordinary caller has no actual call instruction");
        require(!ordinaryCallee.isInline(), "ordinary callee is already marked inline");
        int highBefore = decompile(ordinaryCaller, ordinaryCallee.getEntryPoint(),
            output.resolve("ordinary-before.c"), report);
        require(highBefore > 0, "ordinary call is absent before the analyst flag");
        ordinaryCallee.setInline(true);
        int highAfter;
        try {
            highAfter = decompile(ordinaryCaller, ordinaryCallee.getEntryPoint(),
                output.resolve("ordinary-after.c"), report);
            require(highAfter == 0, "decompiler did not inline the marked ordinary callee");
            require(countRawCalls(ordinaryCaller, ordinaryCallee.getEntryPoint()) == rawBefore,
                "marking inline changed actual call instructions");
        }
        finally {
            ordinaryCallee.setInline(false);
        }
        report.append("ordinary-raw-calls-before-and-after=").append(rawBefore).append('\n');
        report.append("ordinary-high-calls-before=").append(highBefore).append('\n');
        report.append("ordinary-high-calls-after=").append(highAfter).append('\n');
        report.append("inline-evidence-probe=PASS\n");
        Files.writeString(output.resolve("observations.txt"), report, StandardCharsets.UTF_8);
        println(report.toString());
    }

    private Function function(String name) {
        var functions = getGlobalFunctions(name);
        require(functions.size() == 1, "expected one listing function: " + name);
        return functions.get(0);
    }

    private int countRawCalls(Function caller, Address target) {
        int count = 0;
        InstructionIterator instructions = currentProgram.getListing()
            .getInstructions(caller.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (instruction.getFlowType().isCall()) {
                for (Address destination : instruction.getFlows()) {
                    if (destination.equals(target)) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    private int decompile(Function function, Address target, Path cFile,
            StringBuilder report) throws Exception {
        DecompInterface decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "cannot open decompiler");
            DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
            require(result.decompileCompleted() && result.getHighFunction() != null,
                "decompilation failed: " + result.getErrorMessage());
            Files.writeString(cFile, result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
            Map<String, Integer> nodeKinds = new TreeMap<>();
            countNodes(result.getCCodeMarkup(), nodeKinds);
            report.append("decompile=").append(cFile.getFileName())
                .append(" clang-kinds=").append(nodeKinds).append('\n');
            require(nodeKinds.getOrDefault(ClangFunction.class.getSimpleName(), 0) == 1,
                "unexpected Clang function grouping");
            int count = 0;
            Iterator<PcodeOpAST> operations = result.getHighFunction().getPcodeOps();
            while (operations.hasNext()) {
                PcodeOpAST operation = operations.next();
                if (operation.getOpcode() == PcodeOp.CALL && target != null &&
                        operation.getInput(0).getAddress().equals(target)) {
                    count++;
                }
            }
            return count;
        }
        finally {
            decompiler.dispose();
        }
    }

    private void countNodes(ClangNode node, Map<String, Integer> kinds) {
        kinds.merge(node.getClass().getSimpleName(), 1, Integer::sum);
        for (int index = 0; index < node.numChildren(); index++) {
            countNodes(node.Child(index), kinds);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
