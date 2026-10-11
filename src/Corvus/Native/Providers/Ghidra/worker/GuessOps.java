package corvus.ghidra;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;

/** A type for an address without applying it; callers run it inside {@link Worker#read}. */
final class GuessOps {
    private GuessOps() {
    }

    private static JsonObject guess(String type, String method, String confidence) {
        JsonObject o = new JsonObject();
        if (type == null) o.add("type", JsonNull.INSTANCE);
        else o.addProperty("type", type);
        if (method == null) o.add("method", JsonNull.INSTANCE);
        else o.addProperty("method", method);
        o.addProperty("confidence", confidence);
        return o;
    }

    /** {type, method, confidence}: at a function start the decompiler's prototype, else the defined data's type, else one from the item's size. */
    static JsonObject typeGuess(Worker w, Worker.Request r) throws Exception {
        Address a = w.addr(r.args, "rva");
        Function f = w.program.getFunctionManager().getFunctionAt(a);
        if (f != null && Worker.decompilerPresent()) {
            DecompileResults res = CodeOps.results(w, f, w.decompileTimeout, r.monitor);
            if (res.getDecompiledFunction() != null) {
                String sig = res.getDecompiledFunction().getSignature().trim();
                return guess(sig.endsWith(";") ? sig.substring(0, sig.length() - 1) : sig, "decompiler", "high");
            }
        }
        if (f != null) return guess(f.getSignature().getPrototypeString(), "existing", "high");
        Data d = w.program.getListing().getDefinedDataAt(a);
        if (d != null) return guess(d.getDataType().getDisplayName(), "existing", "high");
        CodeUnit u = w.program.getListing().getCodeUnitAt(a);
        if (u instanceof Data data && w.program.getListing().getInstructionAt(a) == null) {
            int size = data.getLength();
            String t = switch (size) {
                case 1 -> "uint8_t";
                case 2 -> "uint16_t";
                case 4 -> "uint32_t";
                case 8 -> "uint64_t";
                default -> "uint8_t[" + size + "]";
            };
            return guess(t, "size", "low");
        }
        return guess(null, null, "none");
    }
}
