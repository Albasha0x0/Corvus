namespace Corvus.Mcp;

// Contract rows of the native-edit family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> NativeEditTools() => new(StringComparer.Ordinal)
    {
        // Native annotations and edits (names and comments are saved to a per-user sidecar file)
        ["rename_native"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["comment_native"] = Changes(destructive: true, idempotent: true, longRunning: true, openWorld: true),
        ["export_native_annotations"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces the file at outputPath
        ["patch_bytes"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["patch_asm"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["list_native_edits"] = Reads(longRunning: true),
        ["undo_native_edit"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["save_native"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces a file (the original's .bak is made once)
        ["export_native_patches"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces the file at outputPath
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> NativeEditTools() => new(StringComparer.Ordinal)
    {
        ["export_native_patches"] = new Dictionary<string, Domain> { ["format"] = Of(["ida", "dif", "ips", "ips32", "json"], "idapython", "py", "diff") },
        ["export_native_annotations"] = new Dictionary<string, Domain> { ["format"] = Of(["ida", "ghidra", "json", "header"], "idapython", "idc", "h") },
        ["rename_native"] = new Dictionary<string, Domain> { ["showDecompile"] = ShowDecompile, ["engine"] = DecompilerEngine },
        ["comment_native"] = new Dictionary<string, Domain> { ["scope"] = Of(["auto", "line", "eol", "pre", "plate", "pseudocode", "function"], "disassembly", "repeatable", "decompiler", "func"), ["engine"] = DecompilerEngine },
        ["patch_bytes"] = new Dictionary<string, Domain> { ["type"] = Of(["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "ptr", "i16be", "u16be", "i32be", "u32be", "i64be", "u64be", "f32be", "f64be"]), ["relocations"] = Relocations, ["stubMode"] = StubMode, ["placement"] = Placement },
        ["patch_asm"] = new Dictionary<string, Domain> { ["relocations"] = Relocations, ["stubMode"] = StubMode, ["placement"] = Placement },
    };
}
