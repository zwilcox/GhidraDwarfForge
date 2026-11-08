package ghidradwarfforge.calls;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.HexFormat;

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
import ghidradwarfforge.unwind.UnwindFlow.Bank;
import ghidradwarfforge.unwind.UnwindFlow.Cell;

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
                var proof = GhidraTailStateProof.verify(program, selected, image, delta, TaskMonitor.DUMMY);
                if (!proof.captures().equals(captured) ||
                        !proof.equals(GhidraTailStateProof.verify(program, selected, image, delta, TaskMonitor.DUMMY))) {
                    throw new AssertionError("saved-program tail-state proof was not deterministic");
                }
                var tails = new ArrayList<Object>();
                for (var tail : proof.tails()) {
                    var item = new LinkedHashMap<String, Object>();
                    item.put("caller", program.getFunctionManager().getFunctionAt(tail.caller()).getName());
                    item.put("callee", program.getFunctionManager().getFunctionAt(tail.callee()).getName());
                    item.put("pc", Long.toHexString(AddressNormalizer.toElfAddress(tail.instruction().getOffset(), delta)));
                    item.put("profile", tail.profile());
                    item.put("originalSha256", tail.originalInstructionSha256());
                    tails.add(item);
                }
                var tailOmissions = new LinkedHashMap<String, String>();
                proof.omissions().forEach((entry, reason) ->
                    tailOmissions.put(program.getFunctionManager().getFunctionAt(entry).getName(), reason));
                var arguments = GhidraCallArgumentFlow.analyze(program, proof, image, delta, TaskMonitor.DUMMY);
                if (!arguments.equals(GhidraCallArgumentFlow.analyze(program, proof, image, delta, TaskMonitor.DUMMY))) {
                    throw new AssertionError("argument analysis was not deterministic");
                }
                var argumentRows = new ArrayList<Object>();
                for (var transfer : arguments.transfers().entrySet()) {
                    var item = new LinkedHashMap<String, Object>();
                    item.put("caller", program.getFunctionManager().getFunctionContaining(transfer.getKey()).getName());
                    item.put("pc", Long.toHexString(AddressNormalizer.toElfAddress(transfer.getKey().getOffset(), delta)));
                    var values = new ArrayList<Object>();
                    // Fixture-specific observer: this is not a production parameter-storage mapping.
                    for (String name : image.machine() == 62 ? List.of("EDI", "ESI") : List.of("w0", "w1")) {
                        var register = program.getRegister(name);
                        var value = GhidraCallArgumentFlow.read(transfer.getValue().values(),
                            new Cell(Bank.REGISTER, register.getAddress().getOffset(), 4));
                        values.add(value == null ? null : HexFormat.of().formatHex(value.dwarf(image.is64Bit() ? 8 : 4, image.byteOrder())));
                    }
                    item.put("integerArgumentExpressions", values);
                    argumentRows.add(item);
                }
                var argumentOmissions = new LinkedHashMap<String, String>();
                arguments.omissions().forEach((entry, reason) ->
                    argumentOmissions.put(program.getFunctionManager().getFunctionAt(entry).getName(), reason));
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
                result.put("scope", "Captured transfers, direct tail boundary states and integer register value expressions; no production parameter mapping or DWARF emission proof");
                result.put("rebaseDelta", delta);
                result.put("classOrigin", GhidraCallSiteEvidence.class.getProtectionDomain().getCodeSource().getLocation().toExternalForm());
                result.put("functions", rows);
                result.put("tails", tails);
                result.put("tailOmissions", tailOmissions);
                result.put("arguments", argumentRows);
                result.put("argumentOmissions", argumentOmissions);
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
