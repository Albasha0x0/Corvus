package corvus.ghidra;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

/** What is at an address, instruction by instruction, in the IDA worker's "insn" reply shape; callers hold the read lock. */
final class InsnOps {
    private static final HexFormat HEX = HexFormat.of();
    private static final Pattern SIZE = Pattern.compile("^(byte|word|dword|qword|tword|xmmword|ymmword|zmmword) ptr", Pattern.CASE_INSENSITIVE);
    private static final Pattern TERM = Pattern.compile("([+-]?)\\s*([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|[0-9]+)(?:\\s*\\*\\s*(0x[0-9a-fA-F]+|[0-9]+))?");

    private InsnOps() {
    }

    /** Args: rva, count (1-64). Items: rva, status, head, end, function, kind, text, note, insn. */
    static JsonElement insn(Worker w, Worker.Request r) throws Exception {
        Address a = w.addr(r.args, "rva");
        int count = Math.max(1, Math.min(r.args.has("count") ? r.args.get("count").getAsInt() : 1, 64));
        Listing listing = w.program.getListing();
        JsonArray items = new JsonArray();
        int n = 0;
        while (n < count) {
            r.monitor.checkCancelled();
            Long rva = w.rva(a);
            MemoryBlock block = w.program.getMemory().getBlock(a);
            JsonObject item = new JsonObject();
            item.addProperty("rva", rva == null ? 0 : rva);
            items.add(item);
            if (rva == null || block == null || !block.isInitialized()) {
                item.addProperty("status", "unmapped");
                break;
            }
            Function f = w.program.getFunctionManager().getFunctionContaining(a);
            if (f != null) item.addProperty("function", w.rva(f.getEntryPoint()));
            Instruction covering = listing.getInstructionContaining(a);
            if (covering != null && !covering.getAddress().equals(a)) {
                item.addProperty("status", "mid_instruction");
                item.addProperty("head", w.rva(covering.getAddress()));
                item.addProperty("end", w.rva(covering.getMaxAddress()) + 1);
                if (count == 1) break;
                a = covering.getAddress(); // a walk starts at the covering instruction
                continue;
            }
            n++;
            item.addProperty("head", rva);
            if (covering != null) {
                item.addProperty("status", f != null ? "decoded" : "not_in_function");
                item.add("insn", decode(w, covering));
                a = covering.getMaxAddress().next();
            }
            else if (listing.getDefinedDataContaining(a) instanceof Data data) {
                item.addProperty("status", "data");
                item.addProperty("head", w.rva(data.getAddress()));
                item.addProperty("end", w.rva(data.getMaxAddress()) + 1);
                item.addProperty("kind", dataKind(data));
                item.addProperty("text", dataText(data));
                a = data.getMaxAddress().next();
            }
            else {
                Instruction pseudo = null;
                try {
                    pseudo = new PseudoDisassembler(w.program).disassemble(a);
                }
                catch (Exception e) {
                    // Not decodable.
                }
                if (pseudo == null) {
                    item.addProperty("status", "invalid");
                    break;
                }
                item.addProperty("status", "not_in_function");
                item.addProperty("note", "bytes Ghidra has not defined as code or data");
                item.add("insn", decode(w, pseudo));
                a = a.add(pseudo.getLength());
            }
            if (a == null) break;
        }
        JsonObject o = new JsonObject();
        o.add("items", items);
        return o;
    }

    private static String dataKind(Data d) {
        if (d.hasStringValue()) return "string";
        if (d.isPointer()) return "pointer";
        if (d.isStructure() || d.isUnion()) return "struct";
        return switch (d.getLength()) {
            case 1 -> "byte";
            case 2 -> "word";
            case 4 -> "dword";
            case 8 -> "qword";
            default -> "data";
        };
    }

    private static String dataText(Data d) {
        String s = d.getDefaultValueRepresentation();
        if (d.isPointer() && d.getValue() instanceof Address target) {
            var symbol = d.getProgram().getSymbolTable().getPrimarySymbol(target);
            return "pointer to " + (symbol != null ? symbol.getName() : target.toString());
        }
        if (s != null && s.length() > 120) s = s.substring(0, 120);
        return s == null ? (d.getLabel() == null ? "" : d.getLabel()) : s;
    }

    private static JsonObject decode(Worker w, Instruction ins) throws Exception {
        JsonObject o = new JsonObject();
        o.addProperty("size", ins.getLength());
        o.addProperty("bytes", HEX.formatHex(ins.getBytes()));
        String text;
        try {
            text = CodeUnitFormat.DEFAULT.getRepresentationString(ins);
        }
        catch (RuntimeException e) {
            text = ins.toString(); // a pseudo instruction outside the listing
        }
        o.addProperty("text", text);
        o.addProperty("mnemonic", ins.getMnemonicString().toLowerCase());
        List<Object> results = List.of(ins.getResultObjects());
        List<Object> inputs = List.of(ins.getInputObjects());
        FlowType flow = ins.getFlowType();
        JsonArray operands = new JsonArray();
        Long branch = null;
        for (int i = 0; i < ins.getNumOperands(); i++) {
            JsonObject op = operand(w, ins, i, flow, results, inputs);
            if ("near_branch".equals(op.has("kind") ? op.get("kind").getAsString() : null) && op.has("target")) branch = op.get("target").getAsLong();
            operands.add(op);
        }
        o.add("operands", operands);
        boolean ret = false;
        for (PcodeOp p : ins.getPcode()) if (p.getOpcode() == PcodeOp.RETURN) ret = true;
        String kind;
        if (ret) kind = "return";
        else if (flow.isCall()) kind = branch != null ? "call" : "indirect_call";
        else if (flow.isJump() && flow.isComputed()) kind = "indirect_jump";
        else if (flow.isJump()) kind = flow.isConditional() ? "conditional_jump" : "jump";
        else if (flow.isTerminal()) kind = "trap";
        else kind = "next";
        o.addProperty("flow", kind);
        if (branch != null) o.addProperty("target", branch);
        Address fall = ins.getFallThrough();
        Long ft = fall != null ? w.rva(fall) : null;
        if (ft != null && !kind.equals("return") && !kind.equals("jump") && !kind.equals("indirect_jump") && !kind.equals("trap")) o.addProperty("fallthrough", ft);
        JsonArray refs = new JsonArray();
        for (Reference ref : ins.getReferencesFrom()) {
            Long to = w.rva(ref.getToAddress());
            if (to == null || ref.getReferenceType().isFallthrough()) continue;
            JsonArray row = new JsonArray();
            row.add(to);
            row.add(CodeOps.xrefKind(ref.getReferenceType()));
            refs.add(row);
        }
        o.add("references", refs);
        return o;
    }

    /** One operand: kind, text, size, access, register, or memory as base, index, scale and displacement (from Ghidra's operand text). */
    private static JsonObject operand(Worker w, Instruction ins, int i, FlowType flow, List<Object> results, List<Object> inputs) {
        JsonObject o = new JsonObject();
        o.addProperty("index", i);
        String text = ins.getDefaultOperandRepresentation(i);
        o.addProperty("text", text);
        Object[] objects = ins.getOpObjects(i);
        List<Register> registers = new ArrayList<>();
        List<Scalar> scalars = new ArrayList<>();
        Address address = null;
        for (Object x : objects) {
            if (x instanceof Register reg) registers.add(reg);
            else if (x instanceof Scalar s) scalars.add(s);
            else if (x instanceof Address ad) address = ad;
        }
        boolean memory = text.contains("[");
        if (memory) {
            o.addProperty("kind", "memory");
            Matcher size = SIZE.matcher(text.trim());
            if (size.find()) o.addProperty("size", switch (size.group(1).toLowerCase()) {
                case "byte" -> 1;
                case "word" -> 2;
                case "dword" -> 4;
                case "qword" -> 8;
                case "tword" -> 10;
                case "xmmword" -> 16;
                case "ymmword" -> 32;
                default -> 64;
            });
            memoryParts(w, o, text.substring(text.indexOf('[') + 1, text.lastIndexOf(']') > text.indexOf('[') ? text.lastIndexOf(']') : text.length()));
            RefType rt = ins.getOperandRefType(i);
            o.addProperty("access", rt.isRead() && rt.isWrite() ? "read_write" : rt.isWrite() ? "write" : rt.isRead() ? "read" : "none");
            if (address != null && !o.has("target") && w.rva(address) != null && registers.isEmpty()) o.addProperty("target", w.rva(address));
            for (Reference ref : ins.getOperandReferences(i))
                if (!ref.getReferenceType().isFlow() && w.rva(ref.getToAddress()) != null) {
                    o.addProperty("target", w.rva(ref.getToAddress()));
                    break;
                }
        }
        else if (address != null && (flow.isCall() || flow.isJump())) {
            o.addProperty("kind", "near_branch");
            Long t = w.rva(address);
            if (t != null) o.addProperty("target", t);
        }
        else if (registers.size() == 1 && scalars.isEmpty() && address == null) {
            Register reg = registers.get(0);
            o.addProperty("kind", "register");
            o.addProperty("register", reg.getName().toLowerCase());
            o.addProperty("size", reg.getMinimumByteSize());
            boolean read = inputs.contains(reg), written = results.contains(reg);
            o.addProperty("access", read && written ? "read_write" : written ? "write" : read ? "read" : "none");
        }
        else if (!scalars.isEmpty() && registers.isEmpty()) {
            o.addProperty("kind", "immediate");
            o.add("value", Worker.u64(scalars.get(0).getUnsignedValue()));
            o.addProperty("access", "read");
        }
        else if (address != null) {
            o.addProperty("kind", "memory");
            Long t = w.rva(address);
            if (t != null) o.addProperty("target", t);
        }
        else o.addProperty("kind", "other");
        return o;
    }

    /** "RAX + RCX*0x8 + 0x10" (Ghidra x86 syntax) or "x1, #0x10" (AArch64): base, index_register, scale, displacement. */
    private static void memoryParts(Worker w, JsonObject o, String inside) {
        String s = inside.contains(":") && !inside.startsWith("0x") ? inside.substring(inside.indexOf(':') + 1) : inside;
        s = s.replace(",", " + ").replace("#", "");
        Matcher m = TERM.matcher(s);
        long displacement = 0;
        boolean any = false;
        while (m.find()) {
            String sign = m.group(1), term = m.group(2), scale = m.group(3);
            boolean number = term.startsWith("0x") || Character.isDigit(term.charAt(0));
            if (!number && w.program.getRegister(term) != null) {
                if (scale != null || o.has("base")) {
                    o.addProperty("index_register", term.toLowerCase());
                    o.addProperty("scale", scale == null ? 1 : number(scale));
                }
                else o.addProperty("base", term.toLowerCase());
            }
            else if (number) {
                long v = number(term);
                displacement += "-".equals(sign) ? -v : v;
                any = true;
            }
        }
        if (any) o.addProperty("displacement", displacement);
    }

    private static long number(String s) {
        return s.startsWith("0x") ? Long.parseUnsignedLong(s.substring(2), 16) : Long.parseLong(s);
    }
}
