// Type creation: C declarations through CParser resolved into the program's data type manager with the replace
// handler, prototypes through Ghidra's signature parsing, and types parsed against the program's manager so pointer
// sizes follow its data organization.
package corvus.ghidra;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;

/** Types in the program's data type manager; callers run the writes inside {@link Worker#write}. */
final class TypeOps {
    /** Program option: the RVAs the user typed (hex, comma separated); recovered types leave them alone. */
    static final String USER_TYPED = "user_typed";
    /** Program option: the user's declarations, applied again after recovered types so they win. */
    static final String USER_DECLS = "user_decls";
    /** Where class and vftable types the server builds are kept. */
    static final CategoryPath CLASSES = new CategoryPath("/corvus/classes");
    private static final CategoryPath SLOTS = new CategoryPath("/corvus/slots");

    private TypeOps() {
    }

    /** Declarations parsed: errors with the parser's messages, and the names of the types made. */
    static final class Parsed {
        int errors;
        final List<String> messages = new ArrayList<>();
        final List<String> names = new ArrayList<>();
    }

    /**
     * Parses C declarations into the program's data type manager, one top-level declaration at a time so an error
     * costs that declaration only; a type of the same name is replaced.
     */
    static Parsed parseDeclarations(Worker w, String text) {
        Parsed result = new Parsed();
        CParser parser = new CParser(w.program.getDataTypeManager(), true, null);
        for (String statement : statements(text)) {
            Set<String> before = known(parser);
            try {
                parser.parse(statement);
            }
            catch (Throwable e) { // ParseException, TokenMgrError and the parser's runtime errors
                if (e instanceof VirtualMachineError) throw (VirtualMachineError) e;
                result.errors++;
                if (result.messages.size() < 50) result.messages.add(clip(statement, 60) + ": " + firstLine(e.getMessage()));
                continue;
            }
            for (String name : known(parser))
                if (!before.contains(name) && !result.names.contains(name)) result.names.add(name);
        }
        return result;
    }

    private static Set<String> known(CParser parser) {
        Set<String> names = new HashSet<>(parser.getComposites().keySet());
        names.addAll(parser.getTypes().keySet());
        names.addAll(parser.getEnums().keySet());
        return names;
    }

    /** Top-level declarations ending in ';' at bracket depth 0; comments and preprocessor lines are dropped. */
    static List<String> statements(String text) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int depth = 0;
        boolean lineStart = true;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '/') {
                while (i < text.length() && text.charAt(i) != '\n') i++;
                lineStart = true;
                cur.append('\n');
                continue;
            }
            if (c == '/' && i + 1 < text.length() && text.charAt(i + 1) == '*') {
                int end = text.indexOf("*/", i + 2);
                i = end < 0 ? text.length() : end + 1;
                cur.append(' ');
                continue;
            }
            if (c == '#' && lineStart) {
                while (i < text.length() && text.charAt(i) != '\n') i++;
                continue;
            }
            if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < text.length() && text.charAt(j) != c) j += text.charAt(j) == '\\' ? 2 : 1;
                cur.append(text, i, Math.min(text.length(), j + 1));
                i = j;
                lineStart = false;
                continue;
            }
            cur.append(c);
            if (c == '\n') lineStart = true;
            else if (!Character.isWhitespace(c)) lineStart = false;
            if (c == '{' || c == '(' || c == '[') depth++;
            else if (c == '}' || c == ')' || c == ']') depth = Math.max(0, depth - 1);
            else if (c == ';' && depth == 0) {
                String s = cur.toString().trim();
                if (s.length() > 1) out.add(s);
                cur.setLength(0);
            }
        }
        if (!cur.toString().isBlank()) out.add(cur.toString().trim());
        return out;
    }

    static String firstLine(String s) {
        if (s == null) return "parse error";
        int nl = s.indexOf('\n');
        return clip(nl < 0 ? s : s.substring(0, nl), 200);
    }

    static String clip(String s, int n) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }

    static Set<Long> userTyped(Worker w) {
        Set<Long> set = new TreeSet<>();
        String text = w.program.getOptions(Worker.STAMPS).getString(USER_TYPED, "");
        if (text != null && !text.isEmpty())
            for (String part : text.split(",")) set.add(Long.parseLong(part, 16));
        return set;
    }

    static void setUserTyped(Worker w, Set<Long> set) {
        StringBuilder sb = new StringBuilder();
        for (long rva : set) {
            if (sb.length() > 0) sb.append(',');
            sb.append(Long.toHexString(rva));
        }
        w.program.getOptions(Worker.STAMPS).setString(USER_TYPED, sb.toString());
    }

    /** The user's declarations again, so they win over recovered types of the same name. */
    static void reapplyUserDeclarations(Worker w) {
        String kept = w.program.getOptions(Worker.STAMPS).getString(USER_DECLS, "");
        if (kept != null && !kept.isEmpty()) parseDeclarations(w, kept);
        TypeEditOps.reapply(w);
        EditOps.reapplyEnums(w);
        TypeEditOps.reapplyFields(w);
    }

    /** A C prototype ("int __fastcall f(Foo *p)") as a function definition, parsed against the program's types; null when it does not parse. */
    static FunctionDefinitionDataType prototype(Program program, String text) {
        String t = text.trim();
        while (t.endsWith(";")) t = t.substring(0, t.length() - 1).trim();
        // IDA's __noreturn (or C's noreturn spellings) marks the function; Ghidra's parser takes no such keyword
        java.util.regex.Matcher noReturn = NO_RETURN.matcher(t);
        boolean exits = noReturn.find();
        if (exits) t = noReturn.replaceAll(" ").replaceAll("\\s+", " ").trim();
        PARSE_ERROR.remove();
        try {
            FunctionDefinitionDataType sig = CParserUtils.parseSignature((ghidra.app.services.DataTypeManagerService) null, program, t, false);
            if (sig != null && exits) sig.setNoReturn(true);
            return sig;
        }
        catch (Throwable e) {
            if (e instanceof VirtualMachineError) throw (VirtualMachineError) e;
            PARSE_ERROR.set(e.getMessage());
            return null;
        }
    }

    private static final ThreadLocal<String> PARSE_ERROR = new ThreadLocal<>();

    private static final java.util.regex.Pattern CONVENTION =
        java.util.regex.Pattern.compile("\\b__(cdecl|stdcall|fastcall|thiscall|vectorcall|pascal|regcall|swiftcall|usercall|userpurge)\\b");

    /**
     * Why a prototype was refused: a calling convention the compiler spec lacks (with the ones it has), else the parser's
     * message from the last prototype() on this thread, else null.
     */
    static String prototypeError(Program program, String text) {
        var names = new java.util.TreeSet<String>();
        for (var model : program.getCompilerSpec().getCallingConventions()) names.add(model.getName());
        java.util.regex.Matcher m = CONVENTION.matcher(text);
        while (m.find())
            if (!names.contains(m.group()))
                return "unknown calling convention " + m.group() + " for " + program.getCompilerSpec().getCompilerSpecID() + "; it has " + String.join(", ", names);
        String parser = PARSE_ERROR.get();
        if (parser == null) return null;
        parser = parser.replaceAll("\\s+", " ").trim();
        return parser.length() > 300 ? parser.substring(0, 300) + "..." : parser;
    }

    private static final java.util.regex.Pattern NO_RETURN =
        java.util.regex.Pattern.compile("\\b__noreturn\\b|\\b_Noreturn\\b|\\[\\[\\s*noreturn\\s*\\]\\]|__attribute__\\s*\\(\\(\\s*noreturn\\s*\\)\\)|__declspec\\s*\\(\\s*noreturn\\s*\\)");

    /** Applies a prototype to the function at the address (created when none starts there), keeping its name. */
    static String applyPrototype(Worker w, Address a, FunctionDefinitionDataType sig, SourceType source, Worker.Request r) {
        FunctionManager fm = w.program.getFunctionManager();
        if (fm.getFunctionAt(a) == null && !new CreateFunctionCmd(a).applyTo(w.program, r.monitor))
            return "no function could be created there";
        boolean wasNoReturn = fm.getFunctionAt(a).hasNoReturn();
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(a, sig, source, false, false, DataTypeConflictHandler.DEFAULT_HANDLER,
            FunctionRenameOption.NO_CHANGE);
        if (!cmd.applyTo(w.program, r.monitor)) return cmd.getStatusMsg() == null ? "Ghidra did not apply the prototype" : cmd.getStatusMsg();
        Function f = fm.getFunctionAt(a);
        // a prototype without a convention (DWARF, a plain C declaration) gets the compiler spec's default, not "unknown"
        // with locked storage, which the decompiler warns about in every function
        if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(f.getCallingConventionName())) {
            try { f.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING); }
            catch (ghidra.util.exception.InvalidInputException e) { }
        }
        f.setNoReturn(sig.hasNoReturn());
        if (sig.hasNoReturn() != wasNoReturn) callSites(w, a, sig.hasNoReturn());
        return null;
    }

    /** A no-return function's call sites lose their fallthrough (the caller's flow stops there); clearing the mark restores it. */
    private static void callSites(Worker w, Address entry, boolean noReturn) {
        for (var ref : w.program.getReferenceManager().getReferencesTo(entry)) {
            if (!ref.getReferenceType().isCall()) continue;
            var insn = w.program.getListing().getInstructionAt(ref.getFromAddress());
            if (insn == null) continue;
            if (noReturn) insn.setFallThrough(null);
            else insn.clearFallThroughOverride();
        }
    }

    /**
     * Recovered types (PDB, RTTI classes, Il2Cpp). Args: decls (C text), prototypes [[rva, declaration]], classes
     * {ptr, classes [{name, vftables [[offset, rva, [slots]]], bases [[name, offset]]}], methods [[rva, class]]},
     * stamp_key, stamp. Builds a &lt;class&gt;_vftable struct per vftable (slots typed from their targets' signatures),
     * a &lt;class&gt; struct (vftable pointers and base subobjects at their offsets), types the vftables and gives the
     * methods a first argument this of the class's pointer type. Addresses the user typed are left alone.
     */
    static JsonObject applyTypes(Worker w, Worker.Request r) {
        long start = System.nanoTime();
        JsonObject a = r.args;
        int declErrors = 0, typed = 0, typeFailures = 0;
        JsonArray failures = new JsonArray();
        Set<Long> user = userTyped(w);
        if (a.has("decls") && !a.get("decls").isJsonNull() && !a.get("decls").getAsString().isBlank())
            declErrors += parseDeclarations(w, a.get("decls").getAsString()).errors;
        for (JsonElement e : Worker.array(a, "prototypes")) {
            JsonArray p = e.getAsJsonArray();
            long rva = p.get(0).getAsLong();
            if (user.contains(rva)) continue;
            String decl = p.get(1).getAsString();
            FunctionDefinitionDataType sig = prototype(w.program, decl);
            String error = sig == null ? "does not parse" : applyPrototype(w, w.space().getAddress(w.base + rva), sig, SourceType.IMPORTED, r);
            if (error == null) typed++;
            else {
                typeFailures++;
                if (failures.size() < 20) failures.add("rva 0x" + Long.toHexString(rva).toUpperCase() + ": " + decl);
            }
        }
        Counts counts = new Counts();
        if (a.has("classes") && a.get("classes").isJsonObject()) classes(w, a.getAsJsonObject("classes"), user, counts);
        if (a.has("decls") || a.has("classes")) reapplyUserDeclarations(w);
        w.setStamp(a);
        JsonObject o = new JsonObject();
        o.addProperty("decl_errors", declErrors);
        o.addProperty("typed", typed);
        o.addProperty("type_failures", typeFailures);
        o.add("failures", failures);
        o.addProperty("structs", counts.structs);
        o.addProperty("vftables_typed", counts.vftables);
        o.addProperty("methods_typed", counts.methods);
        JsonObject skips = new JsonObject();
        for (Map.Entry<String, Integer> s : counts.skips.entrySet()) skips.addProperty(s.getKey(), s.getValue());
        o.add("method_skips", skips);
        o.addProperty("seconds", Math.round((System.nanoTime() - start) / 1e6) / 1000.0);
        return o;
    }

    private static final class Counts {
        int structs, vftables, methods;
        final Map<String, Integer> skips = new TreeMap<>();

        void skip(String reason) {
            skips.merge(reason, 1, Integer::sum);
        }
    }

    private static void classes(Worker w, JsonObject model, Set<Long> user, Counts counts) {
        DataTypeManager dtm = w.program.getDataTypeManager();
        int ptr = model.has("ptr") ? model.get("ptr").getAsInt() : w.program.getDefaultPointerSize();
        List<JsonObject> classes = new ArrayList<>();
        for (JsonElement e : Worker.array(model, "classes")) classes.add(e.getAsJsonObject());
        // empty structs first, so pointers to every class and vftable resolve
        Map<String, DataType> byName = new HashMap<>();
        for (JsonObject c : classes) {
            String name = c.get("name").getAsString();
            byName.put(name, existingOrEmpty(dtm, name));
        }
        FunctionManager fm = w.program.getFunctionManager();
        for (JsonElement e : Worker.array(model, "methods")) {
            JsonArray m = e.getAsJsonArray();
            long rva = m.get(0).getAsLong();
            DataType cls = byName.get(m.get(1).getAsString());
            Function f = fm.getFunctionAt(w.space().getAddress(w.base + rva));
            if (cls == null) {
                counts.skip("no_class_type");
                continue;
            }
            if (f == null || f.isThunk() || f.isExternal()) {
                counts.skip("not_own_function");
                continue;
            }
            // a type set on purpose (PDB, user, a pushed prototype) is kept
            if (user.contains(rva) || f.getSignatureSource() == SourceType.USER_DEFINED || f.getSignatureSource() == SourceType.IMPORTED) {
                counts.skip("typed");
                continue;
            }
            if (setThis(w, f, new PointerDataType(cls, ptr, dtm))) counts.methods++;
            else counts.skip("rejected");
        }
        for (JsonObject c : classes) {
            String name = c.get("name").getAsString();
            TreeMap<Integer, DataType> vftables = new TreeMap<>();
            for (JsonElement e : Worker.array(c, "vftables")) {
                JsonArray v = e.getAsJsonArray();
                int offset = v.get(0).getAsInt();
                long vrva = v.get(1).getAsLong();
                String vname = offset == 0 ? name + "_vftable" : name + "_vftable_" + Integer.toHexString(offset).toUpperCase();
                StructureDataType s = new StructureDataType(CLASSES, vname, 0, dtm);
                Set<String> used = new HashSet<>();
                JsonArray slots = v.get(2).getAsJsonArray();
                for (int i = 0; i < slots.size(); i++) {
                    Function target = fm.getFunctionAt(w.space().getAddress(w.base + slots.get(i).getAsLong()));
                    String member = target != null ? identifier(target.getName()) : "";
                    if (member.isEmpty() || member.length() > 120 || !used.add(member)) member = "slot_" + i;
                    used.add(member);
                    DataType slotType = target != null
                        ? new PointerDataType(new FunctionDefinitionDataType(SLOTS, vname + "_" + member, target.getSignature(), dtm), ptr, dtm)
                        : new PointerDataType(VoidDataType.dataType, ptr, dtm);
                    s.add(slotType, ptr, member, null);
                }
                if (slots.isEmpty()) continue;
                DataType vt = dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                counts.structs++;
                vftables.put(offset, vt);
                if (!user.contains(vrva)) {
                    try {
                        DataUtilities.createData(w.program, w.space().getAddress(w.base + vrva), vt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                        counts.vftables++;
                    }
                    catch (Exception ex) {
                        // code or other data in the way: the struct still describes the class
                    }
                }
            }
            // vftable pointers, then base subobjects at their offsets (a base holds its own vftable pointer)
            TreeMap<Integer, Object[]> members = new TreeMap<>();
            for (Map.Entry<Integer, DataType> v : vftables.entrySet())
                members.put(v.getKey(), new Object[] { v.getKey() == 0 ? "__vftable" : "__vftable_" + Integer.toHexString(v.getKey()).toUpperCase(),
                    new PointerDataType(v.getValue(), ptr, dtm) });
            for (JsonElement e : Worker.array(c, "bases")) {
                JsonArray b = e.getAsJsonArray();
                DataType base = byName.get(b.get(0).getAsString());
                int offset = b.get(1).getAsInt();
                if (base == null || offset < 0 || base.isNotYetDefined() || base.getLength() <= 0) continue;
                members.put(offset, new Object[] { "__base_" + b.get(0).getAsString(), base });
            }
            int end = 0;
            List<Object[]> clean = new ArrayList<>();
            for (Map.Entry<Integer, Object[]> m : members.entrySet()) {
                if (m.getKey() < end) continue;
                DataType t = (DataType) m.getValue()[1];
                clean.add(new Object[] { m.getKey(), m.getValue()[0], t });
                end = m.getKey() + Math.max(1, t.getLength());
            }
            if (clean.isEmpty()) continue;
            StructureDataType s = new StructureDataType(CLASSES, name, end, dtm);
            for (Object[] m : clean) {
                DataType t = (DataType) m[2];
                s.replaceAtOffset((Integer) m[0], t, t.getLength(), (String) m[1], null);
            }
            byName.put(name, dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER));
            counts.structs++;
        }
    }

    /** The named type when it exists, else an empty struct of that name in the class category. */
    private static DataType existingOrEmpty(DataTypeManager dtm, String name) {
        DataType found = dtm.getDataType(CLASSES, name);
        if (found != null) return found;
        List<DataType> list = new ArrayList<>();
        dtm.findDataTypes(name, list);
        for (DataType d : list)
            if (d instanceof Structure) return d;
        return dtm.resolve(new StructureDataType(CLASSES, name, 0, dtm), DataTypeConflictHandler.KEEP_HANDLER);
    }

    /** The first parameter becomes this, of the given type; one is added to a function without parameters. */
    private static boolean setThis(Worker w, Function f, DataType type) {
        try {
            List<Variable> params = new ArrayList<>();
            Parameter[] existing = f.getParameters();
            params.add(new ParameterImpl("this", type, w.program));
            for (int i = 1; i < existing.length; i++) params.add(new ParameterImpl(existing[i].getName(), existing[i].getDataType(), w.program));
            f.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    /** A C identifier from a symbol name (other characters become _). */
    static String identifier(String text) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) sb.append(c < 128 && (Character.isLetterOrDigit(c) || c == '_') ? c : '_');
        String s = sb.toString().replaceAll("^_+|_+$", "");
        if (s.isEmpty()) return "";
        return Character.isDigit(s.charAt(0)) ? "_" + s : s;
    }

    /**
     * A C type ("int[4]", "struct Packet *", "Handler *[8]") parsed against the program's types; null when it does not parse.
     * Names Ghidra's parser rejects are looked up as C and Windows spellings (unsigned __int64, DWORD_PTR, LPCWSTR), as
     * P/LP/LPC pointer typedefs of a known type, without the tag's leading underscore, and case-insensitively.
     */
    static DataType parseType(Worker w, String text) {
        String t = strip(text);
        DataTypeManager dtm = w.program.getDataTypeManager();
        DataType dt = parse(dtm, t);
        if (dt != null) return dt;
        Matcher m = DECLARATOR.matcher(t.replaceAll("\\b(const|volatile)\\b", " ").trim());
        if (!m.matches()) return null;
        DataType base = named(w, m.group(1).trim().replaceAll("\\s+", " "), true);
        if (base == null) return null;
        String suffix = m.group(2).replaceAll("\\s", "");
        if (suffix.matches(".*\\].*\\*.*")) return null; // a pointer after a dimension is not a C type
        for (char c : suffix.toCharArray())
            if (c == '*') base = new PointerDataType(base, dtm);
        List<Integer> dims = new ArrayList<>();
        Matcher d = DIM.matcher(suffix);
        while (d.find()) dims.add(Integer.parseInt(d.group(1)));
        for (int i = dims.size() - 1; i >= 0; i--) {
            if (dims.get(i) <= 0 || base.getLength() <= 0) return null;
            base = new ArrayDataType(base, dims.get(i), base.getLength(), dtm);
        }
        return base;
    }

    /** As {@link #parseType} without the name fallbacks, for lookups that must not land on a similar type (enum upserts). */
    static DataType parseExact(Worker w, String text) {
        return parse(w.program.getDataTypeManager(), strip(text));
    }

    private static String strip(String text) {
        String t = text.trim();
        while (t.endsWith(";")) t = t.substring(0, t.length() - 1).trim();
        return t.replaceAll("\\b(struct|union|enum|class)\\s+", "");
    }

    private static DataType parse(DataTypeManager dtm, String t) {
        try {
            return new DataTypeParser(dtm, dtm, null, DataTypeParser.AllowedDataTypes.FIXED_LENGTH).parse(t);
        }
        catch (Exception e) {
            return null;
        }
    }

    /** A base name followed by pointer stars and array dimensions. */
    private static final Pattern DECLARATOR = Pattern.compile("([A-Za-z_][\\w ]*?)\\s*((?:\\*|\\[\\s*\\d+\\s*\\]|\\s)*)");
    private static final Pattern DIM = Pattern.compile("\\[\\s*(\\d+)\\s*\\]");

    /** C and Windows spellings Ghidra's parser does not take, by lowercase name; "ptr"/"sptr" are pointer-sized integers. */
    private static final Map<String, String> ALIASES = aliases();

    private static Map<String, String> aliases() {
        Map<String, String> m = new HashMap<>();
        String[][] groups = {
            { "ulonglong", "unsigned __int64", "unsigned long long", "unsigned long long int", "__uint64", "uint64_t", "uint64", "dword64", "ulong64",
                "dwordlong" },
            { "longlong", "__int64", "signed __int64", "long long", "signed long long", "long long int", "int64_t", "int64", "long64" },
            { "uint", "unsigned __int32", "unsigned", "uint32_t", "uint32", "dword32", "ulong32" },
            { "int", "__int32", "signed", "signed int", "int32_t", "int32", "long32" },
            { "ushort", "unsigned __int16", "unsigned short", "unsigned short int", "uint16_t" },
            { "short", "__int16", "signed short", "short int", "int16_t" },
            { "uchar", "unsigned __int8", "unsigned char", "uint8_t", "boolean" },
            { "char", "__int8", "int8_t" },
            { "wchar_t", "wchar", "__wchar_t" },
            { "bool", "_bool" },
            { "void *", "handle", "pvoid", "lpvoid", "lpcvoid", "hmodule", "hinstance", "hwnd", "hkey" },
            { "char *", "lpstr", "pstr", "lpcstr", "pcstr", "pchar" },
            { "wchar_t *", "lpwstr", "pwstr", "lpcwstr", "pcwstr", "pwchar", "bstr" },
            { "ptr", "ulong_ptr", "uint_ptr", "dword_ptr", "size_t", "uintptr_t" },
            { "sptr", "long_ptr", "int_ptr", "ssize_t", "intptr_t", "ptrdiff_t" },
        };
        for (String[] g : groups)
            for (int i = 1; i < g.length; i++) m.put(g[i], g[0]);
        return m;
    }

    /** Windows typedefs written in capitals: LONG and BOOL are 32-bit whatever the data organization's long is. */
    private static final Map<String, String> WINDOWS = Map.of("bool", "int", "long", "int", "ulong", "uint", "dword", "uint", "word", "ushort",
        "byte", "uchar", "qword", "ulonglong", "void", "void", "char", "char", "int", "int");

    /** A type by name: exact in any category, an alias, a P/LP/LPC pointer typedef, the tag without its underscore, any case. */
    private static DataType named(Worker w, String name, boolean prefixes) {
        DataTypeManager dtm = w.program.getDataTypeManager();
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(name, found);
        if (!found.isEmpty()) return found.get(0);
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        String alias = ALIASES.get(lower);
        if (alias == null && name.equals(name.toUpperCase(java.util.Locale.ROOT))) alias = WINDOWS.get(lower);
        if (alias != null) {
            int ptr = w.program.getDefaultPointerSize();
            if (alias.equals("ptr")) alias = ptr == 8 ? "ulonglong" : "uint";
            else if (alias.equals("sptr")) alias = ptr == 8 ? "longlong" : "int";
            DataType dt = parse(dtm, alias);
            if (dt != null) return dt;
        }
        if (prefixes)
            for (String p : new String[] { "LPC", "LP", "PC", "P" })
                if (name.length() > p.length() + 1 && name.startsWith(p) && Character.isUpperCase(name.charAt(p.length()))) {
                    DataType inner = named(w, name.substring(p.length()), false);
                    if (inner != null) return new PointerDataType(inner, dtm);
                }
        if (name.startsWith("_") && name.length() > 1) {
            DataType untagged = named(w, name.substring(1), false);
            if (untagged != null) return untagged;
        }
        for (var it = dtm.getAllDataTypes(); it.hasNext();) {
            DataType dt = it.next();
            if (dt.getName().equalsIgnoreCase(name)) return dt;
        }
        return null;
    }

    /**
     * The user's types. Args: decls [C text], types [[rva, prototype or type; "" clears]], stack [[function, offset,
     * name, type]], locals [[function, local, stack offset or null, name, type]], stamp_key, stamp. Declarations
     * without errors are kept and applied again after recovered types; typed addresses are left alone by them.
     */
    static JsonObject applyUserTypes(Worker w, Worker.Request r) throws Exception {
        long start = System.nanoTime();
        int commits = w.signatureCommits;
        JsonObject a = r.args;
        int errors = 0;
        JsonArray messages = new JsonArray(), declared = new JsonArray(), items = new JsonArray();
        Options stamps = w.program.getOptions(Worker.STAMPS);
        JsonArray decls = Worker.array(a, "decls");
        if (!decls.isEmpty()) {
            StringBuilder kept = new StringBuilder(stamps.getString(USER_DECLS, ""));
            for (JsonElement e : decls) {
                String d = e.getAsString().trim();
                if (d.isEmpty()) continue;
                Parsed p = parseDeclarations(w, d);
                errors += p.errors;
                for (String m : p.messages)
                    if (messages.size() < 50) messages.add(m);
                for (String n : p.names)
                    if (!declared.contains(new com.google.gson.JsonPrimitive(n))) declared.add(n);
                if (p.errors == 0 && kept.indexOf(d) < 0) kept.append(d).append('\n');
            }
            stamps.setString(USER_DECLS, kept.toString());
        }
        EditOps.before(w, r, items);
        Set<Long> user = userTyped(w);
        for (JsonElement e : Worker.array(a, "types")) {
            JsonArray t = e.getAsJsonArray();
            items.add(applyUserType(w, r, t.get(0).getAsLong(), t.get(1).isJsonNull() ? "" : t.get(1).getAsString().trim(), user));
        }
        setUserTyped(w, user);
        for (JsonElement e : Worker.array(a, "stack")) {
            JsonArray s = e.getAsJsonArray();
            items.add(FrameOps.applyStack(w, s.get(0).getAsLong(), FrameOps.stackAt(w, s, 4), text(s.get(2)), text(s.get(3))));
        }
        JsonArray locals = Worker.array(a, "locals");
        String[] pins = locals.size() > 1 ? FrameOps.pins(w, r, locals) : new String[locals.size()];
        for (int i = 0; i < locals.size(); i++) {
            JsonArray l = locals.get(i).getAsJsonArray();
            items.add(FrameOps.applyLocal(w, r, l.get(0).getAsLong(), l.get(1).getAsString(), l.get(2).isJsonNull() ? null : l.get(2).getAsInt(),
                text(l.get(3)), text(l.get(4)), pins[i], l.size() > 5 ? text(l.get(5)) : null));
        }
        EditOps.after(w, r, items);
        w.setStamp(a);
        JsonObject o = new JsonObject();
        o.addProperty("decl_errors", errors);
        o.add("decl_messages", messages);
        o.add("declared", declared);
        o.add("items", items);
        o.addProperty("signatures", w.signatureCommits - commits);
        o.addProperty("seconds", Math.round((System.nanoTime() - start) / 1e6) / 1000.0);
        return o;
    }

    private static String text(JsonElement e) {
        return e == null || e.isJsonNull() || e.getAsString().isBlank() ? null : e.getAsString().trim();
    }

    /** A prototype at a function start or a type at a global; an empty declaration clears the user type. */
    private static JsonArray applyUserType(Worker w, Worker.Request r, long rva, String decl, Set<Long> user) {
        Address a = w.space().getAddress(w.base + rva);
        if (!w.program.getMemory().contains(a)) return FrameOps.item("type", rva, decl, false, "rva 0x" + hex(rva) + " is not in the image", null, null, null);
        Function f = w.program.getFunctionManager().getFunctionContaining(a);
        boolean function = f != null && f.getEntryPoint().equals(a);
        if (f != null && !function && w.program.getListing().getInstructionAt(a) != null)
            return FrameOps.item("type", rva, decl, false, "rva 0x" + hex(rva) + " is inside the function at rva 0x" + hex(w.rva(f.getEntryPoint())) +
                ": pass the function's start", null, null, null);
        if (decl.isEmpty()) {
            if (function) f.setSignatureSource(SourceType.ANALYSIS);
            else if (w.program.getListing().getDefinedDataAt(a) != null) w.program.getListing().clearCodeUnits(a, a, false);
            user.remove(rva);
            return FrameOps.item("type", rva, "", true, null, null, null, null);
        }
        if (function) {
            FunctionDefinitionDataType sig = prototype(w.program, decl);
            String why = prototypeError(w.program, decl);
            // Ghidra applies a convention its compiler spec lacks as an unknown one: refused instead
            if (why != null && why.startsWith("unknown calling convention")) return FrameOps.item("type", rva, decl, false, why, null, null, null);
            if (sig == null)
                return FrameOps.item("type", rva, decl, false, why != null ? "the prototype does not parse: " + why
                    : "rva 0x" + hex(rva) + " starts a function: give a prototype such as 'int __fastcall f(int a)' (types it names must be declared first)", null, null, null);
            String error = applyPrototype(w, a, sig, SourceType.USER_DEFINED, r);
            if (error != null) return FrameOps.item("type", rva, decl, false, why != null ? error + "; " + why : error, null, null, null);
            user.add(rva);
            return FrameOps.item("type", rva, decl, true, null, null, null, w.program.getFunctionManager().getFunctionAt(a).getPrototypeString(false, true));
        }
        DataType dt = parseType(w, decl);
        if (dt == null) return FrameOps.item("type", rva, decl, false, "the type does not parse (types it names must be declared first)", null, null, null);
        try {
            var data = DataUtilities.createData(w.program, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            user.add(rva);
            return FrameOps.item("type", rva, decl, true, null, null, null, data.getDataType().getDisplayName());
        }
        catch (Exception e) {
            return FrameOps.item("type", rva, decl, false, "Ghidra did not apply the type at rva 0x" + hex(rva) + ": " + e.getMessage(), null, null, null);
        }
    }

    private static String hex(Long v) {
        return v == null ? "?" : Long.toHexString(v).toUpperCase();
    }

    /** struct, union, enum, typedef or func; null for pointers, arrays and built-in types. */
    static String kind(DataType dt) {
        if (dt instanceof Structure) return "struct";
        if (dt instanceof Union) return "union";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum";
        if (dt instanceof TypeDef) return "typedef";
        if (dt instanceof FunctionDefinition) return "func";
        return null;
    }

    private static long size(DataType dt) {
        return dt.isNotYetDefined() || dt.getLength() <= 0 ? -1 : dt.getLength();
    }

    private static int memberCount(DataType dt) {
        if (dt instanceof Composite c) return c.getNumDefinedComponents();
        if (dt instanceof ghidra.program.model.data.Enum e) return e.getCount();
        return 0;
    }

    /** Named types whose name contains filter (case-insensitive), of kind when given (ptr: typedefs of pointers), by name: rows [name, kind, size, members]. */
    static JsonElement listTypes(Worker w, Worker.Request r) throws Exception {
        String filter = text(r.args.get("filter"));
        String wanted = filter == null ? null : filter.toLowerCase();
        String kind = text(r.args.get("kind"));
        int offset = Math.max(0, r.args.has("offset") ? r.args.get("offset").getAsInt() : 0);
        int limit = Math.max(1, r.args.has("limit") ? r.args.get("limit").getAsInt() : 200);
        List<DataType> all = new ArrayList<>();
        w.program.getDataTypeManager().getAllDataTypes(all);
        List<DataType> rows = new ArrayList<>();
        for (DataType dt : all) {
            r.monitor.checkCancelled();
            String k = kind(dt);
            boolean match = kind == null || ("ptr".equals(kind) ? dt instanceof TypeDef td && td.getBaseDataType() instanceof Pointer : kind.equals(k));
            if (k == null || !match || (wanted != null && !dt.getName().toLowerCase().contains(wanted))) continue;
            rows.add(dt);
        }
        rows.sort((x, y) -> {
            int c = x.getName().compareToIgnoreCase(y.getName());
            return c != 0 ? c : x.getPathName().compareTo(y.getPathName());
        });
        JsonArray page = new JsonArray();
        for (int i = offset; i < Math.min(rows.size(), offset + limit); i++) {
            DataType dt = rows.get(i);
            JsonArray row = new JsonArray();
            row.add(dt.getName());
            row.add(kind(dt));
            row.add(size(dt));
            row.add(memberCount(dt));
            page.add(row);
        }
        JsonObject o = new JsonObject();
        o.addProperty("total", rows.size());
        o.add("rows", page);
        return o;
    }

    /** One named type (by name, or by its category path): a C declaration and, for a struct or union, members [offset, name, type, size]. */
    static JsonElement getType(Worker w, Worker.Request r) {
        String name = r.args.get("name").getAsString().trim();
        DataTypeManager dtm = w.program.getDataTypeManager();
        DataType found = null;
        if (name.startsWith("/")) found = dtm.getDataType(name);
        if (found == null) {
            List<DataType> list = new ArrayList<>();
            dtm.findDataTypes(name, list);
            for (DataType d : list)
                if (kind(d) != null) {
                    found = d;
                    break;
                }
        }
        if (found == null || kind(found) == null) throw new Worker.WorkerError("not_found", "no type named " + name);
        JsonArray members = new JsonArray();
        StringBuilder decl = new StringBuilder();
        if (found instanceof Composite c) {
            decl.append(found instanceof Union ? "union " : "struct ").append(found.getName()).append(" {\n");
            for (DataTypeComponent m : c.getDefinedComponents()) {
                String field = m.getFieldName() != null ? m.getFieldName() : m.getDefaultFieldName();
                decl.append("    ").append(declarator(m.getDataType(), field)).append(";  // +0x").append(Integer.toHexString(m.getOffset()).toUpperCase()).append('\n');
                JsonArray row = new JsonArray();
                row.add(m.getOffset());
                row.add(field);
                row.add(m.getDataType().getDisplayName());
                row.add(m.getLength());
                members.add(row);
            }
            decl.append("};");
        }
        else if (found instanceof ghidra.program.model.data.Enum e) {
            decl.append("enum ").append(e.getName()).append(" {\n");
            for (String n : e.getNames()) decl.append("    ").append(n).append(" = 0x").append(Long.toHexString(e.getValue(n)).toUpperCase()).append(",\n");
            decl.append("};");
        }
        else if (found instanceof TypeDef t) decl.append("typedef ").append(declarator(t.getDataType(), t.getName())).append(';');
        else if (found instanceof FunctionDefinition f) decl.append(f.getPrototypeString(true)).append(';');
        JsonObject o = new JsonObject();
        o.addProperty("name", found.getName());
        o.addProperty("kind", kind(found));
        o.addProperty("size", size(found));
        o.addProperty("decl", decl.toString());
        o.add("members", members);
        return o;
    }

    /** "type name" in C, arrays as name[n]. */
    private static String declarator(DataType dt, String name) {
        StringBuilder dims = new StringBuilder();
        while (dt instanceof Array a) {
            dims.append('[').append(a.getNumElements()).append(']');
            dt = a.getDataType();
        }
        return dt.getDisplayName() + " " + name + dims;
    }

    /**
     * Loads a PDB through Ghidra's PDB applicator (types, symbols, then function internals), unless trust_analysis and
     * the auto-analysis loaded one already. On success the names and user-types stamps are dropped (the PDB's names and
     * prototypes replace pushed ones), the stamp is recorded and the program saved by the caller.
     */
    static JsonObject loadPdb(Worker w, Worker.Request r) throws Exception {
        long start = System.nanoTime();
        String path = r.args.get("path").getAsString();
        File file = new File(path);
        if (!file.isFile()) throw new Worker.WorkerError("not_found", "no PDB file at " + path);
        DataTypeManager dtm = w.program.getDataTypeManager();
        int before = dtm.getDataTypeCount(true);
        Options info = w.program.getOptions(Program.PROGRAM_INFO);
        boolean analysis = info.getBoolean(PdbParserConstants.PDB_LOADED, false);
        JsonObject o = new JsonObject();
        o.addProperty("plugin", true);
        o.addProperty("types_before", before);
        boolean loaded, fromAnalysis = false;
        if (r.args.has("trust_analysis") && r.args.get("trust_analysis").getAsBoolean() && analysis) {
            loaded = fromAnalysis = true;
        }
        else {
            // the analyzer runs inside an analysis session (the applicator keeps its state there) and skips a program marked loaded
            info.setBoolean(PdbParserConstants.PDB_LOADED, false);
            PdbUniversalAnalyzer.setPdbFileOption(w.program, file);
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(w.program);
            mgr.scheduleOneTimeAnalysis(new PdbUniversalAnalyzer(), w.program.getMemory());
            mgr.startAnalysis(r.monitor);
            loaded = info.getBoolean(PdbParserConstants.PDB_LOADED, false);
        }
        o.addProperty("loaded", loaded);
        o.addProperty("from_analysis", fromAnalysis);
        o.addProperty("types_after", dtm.getDataTypeCount(true));
        if (loaded) {
            Options stamps = w.program.getOptions(Worker.STAMPS);
            stamps.removeOption("names");
            stamps.removeOption("user_types"); // the PDB's prototypes may replace the user's: push them again
            w.setStamp(r.args);
        }
        o.addProperty("seconds", Math.round((System.nanoTime() - start) / 1e6) / 1000.0);
        return o;
    }
}
