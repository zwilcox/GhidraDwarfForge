package ghidradwarfforge.calls;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraCallParameters;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.types.ProgramTypeModel;

/** A recorded entry carrier proves precisely one address, without expanding its lifetime. */
final class EntryLocationBoundarySmoke {
    private static int checks;

    private EntryLocationBoundarySmoke() { }

    static void check(Program program, ProgramTypeModel model, List<GhidraCallParameters.Entry> entries,
            List<GhidraCallSiteEvidence.FunctionEvidence> captures, TargetRegisterMap registers,
            ElfImage image, long delta, Storage proven) throws Exception {
        long modification = program.getModificationNumber();
        var variable = model.variableStorage().variables().stream()
            .filter(value -> value.kind() == VariableKind.PARAMETER).findFirst().orElseThrow();
        long entry = variable.functionAddress();
        var original = variable.locations().getFirst();
        var omission = original.storage();
        var evidence = original.evidence();
        require(!omission.available() && proven.available(), "entry fixture lacks independent available/omitted controls");
        require(GhidraCallParameters.withEntryLocations(program, null, entries, captures, registers, image, delta,
            TaskMonitor.DUMMY) == null, "absent model acquired inferred locations");
        for (long[] bounds : List.of(new long[] {entry - 4, entry}, new long[] {entry + 1, entry + 4},
                new long[] {entry, entry + 1}, new long[] {entry - 4, entry + 1},
                new long[] {entry - 4, entry + 4}, new long[] {entry, entry + 4})) {
            var input = variable(variable, variable.kind(), variable.byteSize(),
                List.of(new LocationRange(bounds[0], bounds[1], omission, evidence)));
            var inputModel = replace(model, input, model.functions());
            var result = refine(program, inputModel, entries, captures, registers, image, delta);
            var actual = result.variableStorage().variables().getFirst().locations();
            boolean contains = bounds[0] <= entry && entry < bounds[1];
            var coordinates = new ArrayList<List<Long>>();
            var availability = new ArrayList<Boolean>();
            if (!contains) {
                coordinates.add(List.of(bounds[0], bounds[1])); availability.add(false);
            }
            else {
                if (bounds[0] < entry) { coordinates.add(List.of(bounds[0], entry)); availability.add(false); }
                coordinates.add(List.of(entry, entry + 1)); availability.add(true);
                if (entry + 1 < bounds[1]) { coordinates.add(List.of(entry + 1, bounds[1])); availability.add(false); }
            }
            require(actual.stream().map(row -> List.of(row.start(), row.end())).toList().equals(coordinates),
                "entry refinement changed half-open boundaries: " + actual);
            require(actual.stream().map(row -> row.storage().available()).toList().equals(availability),
                "entry proof escaped its single address: " + actual);
            for (var row : actual) {
                require(row.storage().available() ? row.storage().equals(proven) :
                    row.storage().equals(omission) && row.evidence().equals(evidence),
                    "entry refinement changed the carrier or adjacent omission");
                require(row.evidence().confidence() == evidence.confidence(), "entry refinement promoted confidence");
            }
            require(result.equals(refine(program, result, entries, captures, registers, image, delta)),
                "repeating entry refinement changed its result");
            require(input.locations().getFirst().start() == bounds[0] && input.locations().getFirst().end() == bounds[1],
                "entry refinement mutated input ranges");
        }
        var mixed = variable(variable, variable.kind(), variable.byteSize(), List.of(
            new LocationRange(entry - 4, entry, proven, evidence),
            new LocationRange(entry, entry + 1, omission, evidence),
            new LocationRange(entry + 1, entry + 4, proven, evidence)));
        var mixedResult = refine(program, replace(model, mixed, model.functions()), entries, captures, registers, image, delta)
            .variableStorage().variables().getFirst().locations();
        require(mixedResult.size() == 3 && mixedResult.getFirst().equals(mixed.locations().getFirst()) &&
            mixedResult.getLast().equals(mixed.locations().getLast()) && mixedResult.get(1).storage().equals(proven),
            "entry refinement changed adjacent proven ranges");
        var signature = model.functions().getFirst();
        var local = new ProgramTypeModel.LocalVariable(variable.name(), variable.byteSize(),
            entries.getFirst().formal().type(), 0, true, "USER_DEFINED");
        var localSignature = new ProgramTypeModel.FunctionSignature(signature.name(), signature.address(),
            signature.returnType(), List.of(), List.of(local), signature.variadic(), signature.noReturn(),
            signature.callingConvention(), signature.signatureSource());
        var localModel = replace(model, variable(variable, VariableKind.LOCAL, variable.byteSize(), variable.locations()),
            List.of(localSignature));
        require(refine(program, localModel, entries, captures, registers, image, delta).equals(localModel),
            "parameter entry evidence acquired a local-variable location");
        // These inconsistencies are rejected by the public model constructor,
        // before entry refinement can observe them. Keep that invariant intact.
        try {
            replace(model, variable(variable, variable.kind(), variable.byteSize() + 1, variable.locations()), model.functions());
            throw new AssertionError("inconsistent declaration width reached entry refinement");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("size differs from declaration"), "unexpected width rejection");
        }
        try {
            replace(model, variable, List.of());
            throw new AssertionError("missing signature reached entry refinement");
        }
        catch (IllegalArgumentException expected) {
            require(expected.getMessage().contains("missing function"), "unexpected missing-signature rejection");
        }
        var saved = entries.getFirst();
        for (var stale : List.of(
                new GhidraCallParameters.Entry(saved.functionId() + 1, saved.function(), saved.ordinal(),
                    saved.formal(), saved.pieces(), saved.assigned(), saved.indirect()),
                new GhidraCallParameters.Entry(saved.functionId(), saved.function(), model.functions().getFirst().parameters().size(),
                    saved.formal(), saved.pieces(), saved.assigned(), saved.indirect()))) {
            require(refine(program, model, List.of(stale), captures, registers, image, delta).equals(model),
                "stale entry owner/ordinal acquired a formal location");
        }
        var capture = captures.getFirst();
        var noInstructions = new GhidraCallSiteEvidence.FunctionEvidence(capture.function(), capture.body(), List.of(), capture.omissions());
        require(refine(program, model, entries, List.of(noInstructions), registers, image, delta).equals(model),
            "absent entry instruction acquired a location");
        require(program.getModificationNumber() == modification, "entry refinement changed the analyzed program");
        System.out.println("entry-location-boundaries=PASS checks=" + checks);
    }

    private static VariableLocation variable(VariableLocation original, VariableKind kind, long bytes, List<LocationRange> ranges) {
        return new VariableLocation(original.functionName(), original.functionAddress(), original.name(), kind, bytes, ranges);
    }

    private static ProgramTypeModel replace(ProgramTypeModel model, VariableLocation variable,
            List<ProgramTypeModel.FunctionSignature> signatures) {
        return new ProgramTypeModel(model.types(), signatures, model.globals(), new VariableStorageModel(List.of(variable)),
            model.functionStatics(), model.functionDeclarations(), model.lexicalScopes(), model.classScopes(), model.functionRelations());
    }

    private static ProgramTypeModel refine(Program program, ProgramTypeModel model, List<GhidraCallParameters.Entry> entries,
            List<GhidraCallSiteEvidence.FunctionEvidence> captures, TargetRegisterMap registers, ElfImage image, long delta)
            throws Exception {
        return GhidraCallParameters.withEntryLocations(program, model, entries, captures, registers, image, delta, TaskMonitor.DUMMY);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
