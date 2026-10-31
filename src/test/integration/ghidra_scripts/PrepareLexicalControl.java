// Negative lexical evidence controls in a disposable read-only program session.
// @category DWARF.Tests
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
import ghidradwarfforge.GhidraLexicalScopes;

public class PrepareLexicalControl extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("stale or coalesced");
        String mode = getScriptArgs()[0];
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        ghidra.program.model.listing.Function function = null;
        while (functions.hasNext()) {
            var candidate = functions.next();
            if (candidate.getName().equals("scoped")) function = candidate;
        }
        if (function == null) throw new AssertionError("missing scoped function");
        var scope = GhidraLexicalScopes.read(function, monitor, this::println).orElseThrow();
        var inner = Arrays.stream(function.getLocalVariables()).filter(v -> v.getName().equals("shadow_1")).findFirst().orElseThrow();
        if (mode.equals("stale")) {
            inner.setName("stale_shadow", SourceType.USER_DEFINED);
            var diagnostics = new ArrayList<String>();
            if (GhidraLexicalScopes.read(function, monitor, diagnostics::add).isPresent() || diagnostics.isEmpty()) {
                throw new AssertionError("stale identity accepted");
            }
            diagnostics.forEach(this::println);
        }
        else if (mode.equals("coalesced")) {
            var outer = Arrays.stream(function.getLocalVariables()).filter(v -> v.getName().equals("shadow")).findFirst().orElseThrow();
            int first = outer.getFirstUseOffset(), second = inner.getFirstUseOffset();
            for (var variable : function.getLocalVariables()) function.removeVariable(variable);
            String processor = currentProgram.getLanguage().getProcessor().toString();
            var register = currentProgram.getRegister(processor.equals("x86") ? "EAX" : "w9");
            if (register == null || register.getBitLength() != 32) throw new AssertionError("unsupported fixture register");
            // These STORE instructions do not initialize the nominated register.
            // Saved merge identity is valid; physical value proof must stay absent.
            var one = function.addLocalVariable(new LocalVariableImpl("merged", first,
                IntegerDataType.dataType, register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            var two = function.addLocalVariable(new LocalVariableImpl("merged$1", second,
                IntegerDataType.dataType, register, currentProgram, SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            GhidraLexicalScopes.save(function, "Negative control: explicit binding to a subsequently coalesced local",
                scope.blocks(), List.of(new GhidraLexicalScopes.Local(one, "outer", "shadow"),
                    new GhidraLexicalScopes.Local(two, "inner", "shadow")), monitor);
            if (GhidraLexicalScopes.read(function, monitor, this::println).isEmpty()) throw new AssertionError("valid saved bindings lost");
        }
        else throw new IllegalArgumentException("unknown lexical control");
        println("lexical-control-preparation=" + mode + " PASS");
    }
}
