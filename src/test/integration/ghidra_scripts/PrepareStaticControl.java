// Disposable read-only-session mutations must not alter the saved static evidence.
// @category DWARF.Tests
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraLexicalScopes;
import ghidradwarfforge.GhidraStaticBindings;

public class PrepareStaticControl extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String mode = getScriptArgs()[0];
        var bindings = new ArrayList<GhidraStaticBindings.Snapshot>();
        var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getID() <= 0) continue;
            var result = GhidraStaticBindings.read(currentProgram, symbol.getID(), monitor, this::println);
            if (result.status() == GhidraStaticBindings.Status.VALID) bindings.add(result.binding());
        }
        if (bindings.size() != 5) throw new AssertionError("expected five static identities");
        var inner = bindings.stream().filter(b -> b.block().equals("inner")).findFirst().orElseThrow();
        if (mode.equals("stale")) {
            currentProgram.getOptions(GhidraStaticBindings.OPTIONS_NAME).setString("static-" + inner.symbol().getID(), "GDFSB1:!");
        }
        else if (mode.equals("conflict")) {
            var sibling = bindings.stream().filter(b -> b.block().equals("sibling")).findFirst().orElseThrow();
            GhidraStaticBindings.save(currentProgram, sibling.symbol(), sibling.owner(), "inner", "shadow", "deliberate conflicting identity", monitor);
        }
        else if (mode.equals("coalesced")) {
            var function = inner.owner();
            var scope = GhidraLexicalScopes.read(function, monitor, this::println).orElseThrow();
            String processor = currentProgram.getLanguage().getProcessor().toString();
            var register = currentProgram.getRegister(processor.equals("x86") ? "EAX" : "w9");
            if (register == null || register.getBitLength() != 32) throw new AssertionError("unsupported fixture register");
            int first = Math.toIntExact(scope.blocks().stream().filter(b -> b.id().equals("outer")).findFirst().orElseThrow()
                .body().getMinAddress().subtract(function.getEntryPoint()));
            int second = Math.toIntExact(scope.blocks().stream().filter(b -> b.id().equals("inner")).findFirst().orElseThrow()
                .body().getMinAddress().subtract(function.getEntryPoint()));
            var one = function.addLocalVariable(new LocalVariableImpl("merged", first, IntegerDataType.dataType,
                register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            var two = function.addLocalVariable(new LocalVariableImpl("merged$1", second, IntegerDataType.dataType,
                register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            GhidraLexicalScopes.save(function, "Negative control: a lexical local is coalesced during extraction", scope.blocks(),
                List.of(new GhidraLexicalScopes.Local(one, "outer", "merged_shadow"),
                    new GhidraLexicalScopes.Local(two, "inner", "merged_shadow")), monitor);
            for (var binding : bindings) {
                GhidraStaticBindings.save(currentProgram, binding.symbol(), binding.owner(), binding.block(), binding.displayName(),
                    binding.evidence(), monitor);
            }
        }
        else throw new IllegalArgumentException("unknown static control");
        println("static-control-preparation=" + mode + " PASS");
    }
}
