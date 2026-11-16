package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;

import ghidradwarfforge.output.MmioSelection.*;

/** Analyst selection boundaries; this test never reads or claims peripheral behavior. */
public final class MmioSelectionBoundarySmoke {
    private static final String DOCUMENT = """
        {"schema":1,"language":"ARM:LE:32:Cortex","architecture":"arm",
         "transport":{"id":"probe","evidence":"explicit access contract"},
         "registers":[{"name":"status","address":"ram:40000000","runtime_address":"0x40000000",
          "width":4,"read_effect":"read-clear","views":[
           {"name":"raw","datatype":"/uint","offset":0,"qualifiers":["volatile"]}]}]}
        """;
    private static int checks;

    public static void main(String[] args) throws Exception {
        var baseline = MmioSelection.read(DOCUMENT, () -> false);
        var selected = baseline.registers().getFirst();
        require(selected.readEffect().equals("read-clear") && selected.width() == 4 &&
            selected.address().equals("ram:40000000") && selected.runtimeAddress().equals("0x40000000") &&
            selected.views().getFirst().qualifiers().equals(List.of("volatile")), "analyst access semantics changed");
        for (int width : new int[] {1, 2, 4, 8}) {
            for (String policy : List.of("none", "read-clear", "read-increment", "unknown", "write-only")) {
                for (List<String> qualifiers : List.of(List.<String>of(), List.of("const"), List.of("volatile"),
                        List.of("volatile", "const"))) {
                    var json = document();
                    var register = register(json);
                    register.addProperty("width", width);
                    register.addProperty("read_effect", policy);
                    register.addProperty("runtime_address", "0xffffffffffffffff");
                    view(json).addProperty("offset", width - 1);
                    var array = new com.google.gson.JsonArray();
                    qualifiers.forEach(array::add);
                    view(json).add("qualifiers", array);
                    var actual = MmioSelection.read(json.toString(), () -> false).registers().getFirst();
                    require(actual.width() == width && actual.readEffect().equals(policy) &&
                        actual.runtimeAddress().equals("0xffffffffffffffff") &&
                        actual.views().getFirst().offset() == width - 1 &&
                        actual.views().getFirst().qualifiers().equals(qualifiers), "selection was coerced or inferred");
                }
            }
        }
        for (String field : document().keySet()) {
            var json = document(); json.remove(field); reject(json.toString());
        }
        for (String scope : List.of("transport", "register", "view")) {
            var template = scope(document(), scope);
            for (String field : template.keySet()) {
                var json = document(); scope(json, scope).remove(field); reject(json.toString());
            }
            var json = document(); scope(json, scope).addProperty("unexpected", true); reject(json.toString());
        }
        reject(DOCUMENT.replace("\"schema\":1", "\"schema\":2"));
        reject(DOCUMENT.replace("\"schema\":1", "\"schema\":1,\"sch\\u0065ma\":1"));
        reject(DOCUMENT + "{}");
        reject(null);
        reject(" ".repeat(65537));
        for (String number : List.of("-1", "0", "3", "16", "1.5", "2147483648", "\"4\"")) {
            reject(DOCUMENT.replace("\"width\":4", "\"width\":" + number));
        }
        var json = document(); register(json).addProperty("runtime_address", "0x10000000000000000"); reject(json.toString());
        json = document(); register(json).addProperty("read_effect", "read-safe"); reject(json.toString());
        for (String name : new String[] {null, "", "with space", "a".repeat(81)}) {
            rejectModel(() -> selection("lang", "arch", new Transport(name, "evidence"), List.of(selected)));
        }
        for (String language : new String[] {null, "", " "}) {
            rejectModel(() -> selection(language, "arch", baseline.transport(), List.of(selected)));
        }
        for (String architecture : new String[] {null, "", " ", "a".repeat(81)}) {
            rejectModel(() -> selection("lang", architecture, baseline.transport(), List.of(selected)));
        }
        rejectModel(() -> selection("lang", "arch", null, List.of(selected)));
        for (String evidence : new String[] {null, "", " ", "a".repeat(4097)}) {
            rejectModel(() -> selection("lang", "arch", new Transport("probe", evidence), List.of(selected)));
        }
        var bounded = selection("lang", "a".repeat(80), new Transport("p".repeat(80), "e".repeat(4096)), List.of(selected));
        require(bounded.architecture().length() == 80 && bounded.transport().evidence().length() == 4096,
            "exact identity/evidence bounds rejected");
        rejectModel(() -> selection("lang", "arch", baseline.transport(), List.of()));
        rejectModel(() -> selection("lang", "arch", baseline.transport(), List.of(selected, selected)));
        var many = new ArrayList<Register>();
        for (int i = 0; i < 128; i++) many.add(new Register("r" + i, selected.address(), selected.runtimeAddress(),
            4, "unknown", selected.views()));
        require(selection("lang", "arch", baseline.transport(), many).registers().size() == 128, "exact register bound rejected");
        many.add(new Register("extra", selected.address(), selected.runtimeAddress(), 4, "unknown", selected.views()));
        rejectModel(() -> selection("lang", "arch", baseline.transport(), many));
        for (String address : new String[] {null, "", " "}) {
            rejectRegister(baseline, new Register("r", address, "0x1", 4, "unknown", selected.views()));
        }
        for (String address : new String[] {null, "", "1", "0xA", "0x-1"}) {
            rejectRegister(baseline, new Register("r", "ram:1", address, 4, "unknown", selected.views()));
        }
        var views = new ArrayList<View>();
        for (int i = 0; i < 16; i++) views.add(new View("v" + i, "/uint", 0, List.of()));
        require(withViews(baseline, views).registers().getFirst().views().size() == 16, "exact view bound rejected");
        views.add(new View("extra", "/uint", 0, List.of()));
        rejectModel(() -> withViews(baseline, views));
        rejectModel(() -> withViews(baseline, List.of()));
        rejectModel(() -> withViews(baseline, List.of(selected.views().getFirst(), selected.views().getFirst())));
        for (String type : new String[] {null, "", "uint", "/"}) {
            rejectModel(() -> withViews(baseline, List.of(new View("v", type, 0, List.of()))));
        }
        for (int offset : new int[] {-1, 4}) {
            rejectModel(() -> withViews(baseline, List.of(new View("v", "/uint", offset, List.of()))));
        }
        for (var qualifiers : List.of(List.of("restrict"), List.of("const", "const"), List.of("const", "volatile", "restrict"))) {
            rejectModel(() -> withViews(baseline, List.of(new View("v", "/uint", 0, qualifiers))));
        }
        var mutable = new ArrayList<>(selected.views());
        var retained = withViews(baseline, mutable);
        mutable.clear();
        require(retained.registers().getFirst().views().size() == 1, "later caller mutation altered selected views");
        try { MmioSelection.read(DOCUMENT, () -> true); throw new AssertionError("cancelled MMIO selection accepted"); }
        catch (CancellationException expected) { checks++; }
        System.out.println("mmio-selection-boundaries=PASS checks=" + checks);
    }

    private static MmioSelection selection(String language, String architecture, Transport transport, List<Register> registers) {
        return new MmioSelection(language, architecture, transport, registers);
    }
    private static MmioSelection withViews(MmioSelection baseline, List<View> views) {
        return selection(baseline.language(), baseline.architecture(), baseline.transport(),
            List.of(new Register("r", "ram:1", "0x1", 4, "unknown", views)));
    }
    private static void rejectRegister(MmioSelection baseline, Register register) throws Exception {
        rejectModel(() -> selection(baseline.language(), baseline.architecture(), baseline.transport(), List.of(register)));
    }
    private static JsonObject document() { return JsonParser.parseString(DOCUMENT).getAsJsonObject(); }
    private static JsonObject register(JsonObject json) { return json.getAsJsonArray("registers").get(0).getAsJsonObject(); }
    private static JsonObject view(JsonObject json) { return register(json).getAsJsonArray("views").get(0).getAsJsonObject(); }
    private static JsonObject scope(JsonObject json, String name) {
        return switch (name) { case "transport" -> json.getAsJsonObject(name); case "register" -> register(json); default -> view(json); };
    }
    private static void reject(String text) throws Exception {
        try { MmioSelection.read(text, () -> false); throw new AssertionError("invalid MMIO document accepted"); }
        catch (IOException expected) { checks++; }
    }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void rejectModel(Action action) throws Exception {
        try { action.run(); throw new AssertionError("invalid MMIO model accepted"); }
        catch (IllegalArgumentException expected) { checks++; }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}
