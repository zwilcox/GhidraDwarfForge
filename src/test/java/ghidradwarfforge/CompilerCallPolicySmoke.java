package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionDeclaration;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Compiler defaults must not silently redefine the original ELF debugger's ABI. */
public final class CompilerCallPolicySmoke {
    private record Target(String language, String name, String baseline) { }
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var input = model();
        int specifications = 0;
        for (var target : List.of(new Target("x86:LE:64:default", "x86_64", "gcc"),
                new Target("x86:LE:32:default", "x86", "gcc"),
                new Target("AARCH64:LE:64:v8A", "aarch64", "default"),
                new Target("ARM:LE:32:v8", "arm", "default"),
                new Target("MIPS:BE:32:default", "mips", "default"),
                new Target("MIPS:LE:32:default", "mipsel", "default"))) {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
            var description = new DwarfTarget(target.name(), target.name(),
                language.getLanguageDescription().getSize() == 64 ? 8 : 4,
                !language.isBigEndian(), language.getProcessor().toString());
            for (var compiler : language.getCompatibleCompilerSpecDescriptions()) {
                var owner = new Object();
                var program = new ProgramDB("compiler-call-policy", language,
                    language.getCompilerSpecByID(compiler.getCompilerSpecID()), owner);
                try {
                    boolean blocked = !compiler.getCompilerSpecID().toString().equals(target.baseline());
                    var diagnostics = new ArrayList<String>();
                    var output = GhidraCompilerCallPolicy.apply(program, description, input,
                        TaskMonitor.DUMMY, diagnostics::add);
                    require(output.types() == input.types() && output.variableStorage() == input.variableStorage(),
                        "type or storage graph replaced");
                    require(output.globals().equals(input.globals()) && output.functionStatics().equals(input.functionStatics()),
                        "data/ownership changed");
                    require(output.functions().size() == 2 && output.functionDeclarations().size() == 2,
                        "signature inventory changed");
                    for (int i = 0; i < input.functions().size(); i++) {
                        var before = input.functions().get(i);
                        var after = output.functions().get(i);
                        require(after.name().equals(before.name()) && after.address() == before.address() &&
                            after.returnType().equals(before.returnType()) && after.parameters().equals(before.parameters()) &&
                            after.locals().equals(before.locals()) && after.variadic() == before.variadic() &&
                            after.noReturn() == before.noReturn() && after.callingConvention().equals(before.callingConvention()) &&
                            after.signatureSource().equals(before.signatureSource()) &&
                            after.nonDefaultCallingConvention() == before.nonDefaultCallingConvention(), "curated signature changed");
                        require(after.debuggerCallsDisabled() == (blocked || i == 1), "incorrect call restriction");
                        require(after.debuggerCallRestriction().startsWith(before.debuggerCallRestriction()),
                            "existing restriction lost");
                        var decl = output.functionDeclarations().get(i);
                        require(decl.debuggerCallsDisabled() == (blocked || i == 1), "external declaration callable");
                        require(decl.key().equals(input.functionDeclarations().get(i).key()) &&
                            decl.parameters().equals(input.functionDeclarations().get(i).parameters()), "external identity changed");
                    }
                    require(diagnostics.size() == (blocked ? 4 : 0), "missing compiler restriction diagnostics");
                    if (!blocked) require(output == input, "baseline policy did not preserve model");
                    require(output.equals(GhidraCompilerCallPolicy.apply(program, description, output,
                        TaskMonitor.DUMMY, ignored -> { })), "repeated policy accumulated restrictions");
                    var monitor = new TaskMonitorAdapter(true);
                    monitor.cancel();
                    try {
                        GhidraCompilerCallPolicy.apply(program, description, input, monitor, ignored -> { });
                        throw new AssertionError("cancellation ignored");
                    }
                    catch (CancelledException expected) {
                        checks++;
                    }
                    specifications++;
                }
                finally {
                    program.release(owner);
                }
            }
            require(!description.compilerSpecCallRestriction("unregistered").isEmpty(), "unknown compiler accepted");
            System.out.println("compiler-call-policy-target=PASS " + target.language());
        }
        require(input.equals(model()), "input model mutated");
        System.out.println("compiler-call-policy-smoke=PASS checks=" + checks + " specifications=" + specifications);
    }

    private static ProgramTypeModel model() {
        var integer = new TypeRef("integer");
        var types = new TypeGraph(List.of(new BaseType(integer.key(), "int", 4, BaseEncoding.SIGNED)));
        var functions = new ArrayList<FunctionSignature>();
        var declarations = new ArrayList<FunctionDeclaration>();
        for (int index = 0; index < 2; index++) {
            var parameters = List.of(new Parameter("argument", integer, false));
            String reason = index == 0 ? "" : "existing custom restriction";
            functions.add(new FunctionSignature("function" + index, 0x1000 + index * 16, integer,
                parameters, List.of(new ProgramTypeModel.LocalVariable("local", 4, integer, 2, true, "USER_DEFINED")),
                index != 0, index != 0, "default", "USER_DEFINED", index != 0, reason));
            declarations.add(new FunctionDeclaration("external:" + index, "library::function" + index,
                integer, parameters, index != 0, index != 0, "default", "USER_DEFINED", index != 0, reason));
        }
        return new ProgramTypeModel(types, functions,
            List.of(new ProgramTypeModel.GlobalVariable("global", 0x2000, 4, integer, false, "USER_DEFINED")),
            new VariableStorageModel(List.of()),
            List.of(new ProgramTypeModel.FunctionStaticVariable("private", 0x2004, 4, integer, 0x1000, "USER_DEFINED")),
            declarations);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}
