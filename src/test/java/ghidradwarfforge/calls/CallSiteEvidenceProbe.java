package ghidradwarfforge.calls;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import com.google.gson.GsonBuilder;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.elf.ElfImage;

/** Reopens a real analyzed fixture and invokes current production evidence capture. */
public final class CallSiteEvidenceProbe {
    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var project = GhidraProject.openProject(args[1], "Calls");
        try {
            var program = project.openProgram("/", "input", true);
            int transaction = program.startTransaction("temporary call-site capture rebase");
            try {
                long shift = Long.decode(args[4]);
                if (shift != 0) program.setImageBase(program.getImageBase().add(shift), true);
                long delta = AddressNormalizer.rebaseDelta(program.getImageBase().getOffset(), GhidraImageBase.originalImageBase(program));
                var selected = new ArrayList<Function>();
                for (var function : program.getFunctionManager().getFunctions(true)) {
                    if (function.getName().startsWith("cs_")) selected.add(function);
                }
                var image = ElfImage.read(Path.of(args[2]));
                var captured = GhidraCallSiteEvidence.capture(program, selected, image, delta, TaskMonitor.DUMMY);
                if (!captured.equals(GhidraCallSiteEvidence.capture(program, selected, image, delta, TaskMonitor.DUMMY))) {
                    throw new AssertionError("saved-program capture was not deterministic");
                }
                var rows = new ArrayList<Object>();
                for (var function : captured) {
                    var row = new LinkedHashMap<String, Object>();
                    row.put("name", function.function().name());
                    row.put("entry", function.function().entry().toString());
                    row.put("thunk", function.function().thunk());
                    row.put("captureComplete", function.captureComplete());
                    row.put("omissions", function.omissions());
                    var instructions = new ArrayList<Object>();
                    for (var instruction : function.instructions()) {
                        var item = new LinkedHashMap<String, Object>();
                        item.put("address", instruction.address().toString());
                        item.put("elfAddress", Long.toHexString(AddressNormalizer.toElfAddress(instruction.address().getOffset(), delta)));
                        item.put("kind", instruction.transfer().kind().name());
                        item.put("reason", instruction.transfer().reason());
                        item.put("flow", instruction.flow());
                        item.put("defaultFlow", instruction.defaultFlow());
                        item.put("override", instruction.override());
                        item.put("target", instruction.transfer().target() == null ? null : Long.toHexString(
                            AddressNormalizer.toElfAddress(instruction.transfer().target().getOffset(), delta)));
                        item.put("returnPc", instruction.transfer().returnPc() == null ? null : Long.toHexString(
                            AddressNormalizer.toElfAddress(instruction.transfer().returnPc().getOffset(), delta)));
                        item.put("callee", instruction.transfer().callee() == null ? null : instruction.transfer().callee().name());
                        item.put("original", instruction.original());
                        instructions.add(item);
                    }
                    row.put("instructions", instructions);
                    rows.add(row);
                }
                var result = new LinkedHashMap<String, Object>();
                result.put("scope", "Captured transfers and branch candidates only; no tail-state, argument or DWARF emission proof");
                result.put("rebaseDelta", delta);
                result.put("classOrigin", GhidraCallSiteEvidence.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
                result.put("functions", rows);
                Path output = Path.of(args[3]);
                Files.createDirectories(output.getParent());
                Files.writeString(output, new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(result) + "\n",
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                System.out.println("call-site-evidence-probe=PASS functions=" + rows.size() + " delta=" + delta);
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally { project.close(); }
    }
}
