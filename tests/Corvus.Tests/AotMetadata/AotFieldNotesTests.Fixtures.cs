using Corvus.Services;

namespace Corvus.Tests;

public sealed partial class AotFieldNotesTests
{
    // Reads the slot calls of each function, made the entry point of an image
    // whose text starts at RVA 0x1000, as a PE image or an ELF shared object.
    internal Dictionary<string, List<AotSlotNotes.SlotCall>> CallsOf(byte[] text, (string Source, string Script) metadata, IReadOnlyDictionary<string, uint> functions, bool elf = false)
    {
        var calls = new Dictionary<string, List<AotSlotNotes.SlotCall>>();
        foreach (var (name, rva) in functions)
        {
            var (_, _, native, index) = Open(text, 0x8664, elf, source: metadata.Source, script: metadata.Script, store: name, entry: rva - 0x1000);
            calls[name] = AotSlotNotes.Calls(native, index, index.FunctionAt(rva) ?? throw new InvalidOperationException($"no function at {name} 0x{rva:X}"), default);
        }
        return calls;
    }
}
