using System.Collections.Concurrent;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Decodes method bodies from the in-memory image with System.Reflection.Metadata; materializing dnlib bodies costs
/// ~0.1 ms per method and does not scale across threads. Operand tokens resolve through the dnlib module (cached per
/// token), yielding ordinary dnlib <see cref="Instruction"/> objects.
///
/// Used only for assemblies without unsaved edits; otherwise the dnlib module is the source of truth.
/// Locals and parameters are given as int indices, not dnlib Local/Parameter objects.
/// </summary>
public static class FastIlReader
{
    public sealed record Body(IList<Instruction> Instructions, IReadOnlyList<TypeSig> LocalTypes, IReadOnlyList<(ITypeDefOrRef CatchType, uint HandlerOffset)> Catches);

    private static readonly ConditionalWeakTable<ModuleDef, ConcurrentDictionary<uint, object?>> TokenCache = new();

    /// <summary>The method's instructions: fast path for unedited assemblies, dnlib otherwise. Never throws.</summary>
    public static IList<Instruction> Instructions(LoadedAssembly asm, MethodDef method) =>
        Read(asm, method)?.Instructions ?? MetadataUtil.SafeInstructions(method);

    /// <summary>Instructions, local types and catch clauses, or null when there is no body.</summary>
    public static Body? Read(LoadedAssembly asm, MethodDef method)
    {
        if (asm.IsDirty)
            return FromDnlib(method);
        uint rva = (uint)method.RVA;
        if (rva == 0)
            return null;
        try
        {
            var pe = asm.GetPEFile();
            var block = pe.Reader.GetMethodBody((int)rva);
            var module = method.Module;
            var cache = TokenCache.GetValue(module, _ => new ConcurrentDictionary<uint, object?>());
            object? Resolve(uint token) => cache.GetOrAdd(token, t => MetadataUtil.Try(() => module.ResolveToken(t)));

            var instructions = Decode(block.GetILReader(), pe.Metadata, Resolve);
            var locals = new List<TypeSig>();
            // Resolved with the method's generic context (uncached) so generic locals keep their names.
            if (!block.LocalSignature.IsNil
                && MetadataUtil.Try(() => module.ResolveToken((uint)MetadataTokens.GetToken(block.LocalSignature), new GenericParamContext(method.DeclaringType, method)))
                    is StandAloneSig { LocalSig: { } localSig })
                locals.AddRange(localSig.Locals);
            var catches = new List<(ITypeDefOrRef, uint)>();
            foreach (var region in block.ExceptionRegions)
                if (!region.CatchType.IsNil && Resolve((uint)MetadataTokens.GetToken(region.CatchType)) is ITypeDefOrRef catchType)
                    catches.Add((catchType, (uint)region.HandlerOffset));
            return new Body(instructions, locals, catches);
        }
        catch
        {
            return null; // unreadable body header (corrupt image): treat as no body
        }
    }

    private static Body? FromDnlib(MethodDef method)
    {
        var body = MetadataUtil.SafeBody(method);
        if (body == null) return null;
        return new Body(body.Instructions, body.Variables.Select(v => v.Type).ToList(),
            body.ExceptionHandlers.Where(h => h.CatchType != null).Select(h => (h.CatchType, h.HandlerStart?.Offset ?? 0)).ToList());
    }

    private static List<Instruction> Decode(BlobReader reader, MetadataReader metadata, Func<uint, object?> resolve)
    {
        var list = new List<Instruction>();
        var branches = new List<(Instruction Instr, object Targets, int Next)>();
        // Corrupt bodies (memory-dumped or transformed images) stop at the first invalid opcode or truncated operand;
        // instructions read so far are kept.
        while (reader.RemainingBytes > 0)
        {
            int offset = reader.Offset;
            byte first = reader.ReadByte();
            if (first == 0xFE && reader.RemainingBytes == 0) break;
            var op = first == 0xFE ? OpCodes.TwoByteOpCodes[reader.ReadByte()] : OpCodes.OneByteOpCodes[first];
            if (op.Code is Code.UNKNOWN1 or Code.UNKNOWN2 || reader.RemainingBytes < OperandSize(op.OperandType)) break;
            var instr = new Instruction(op) { Offset = (uint)offset };
            object? branchTargets = null; // relative to the end of this instruction
            switch (op.OperandType)
            {
                case OperandType.InlineNone:
                case OperandType.InlinePhi:
                    break;
                case OperandType.ShortInlineBrTarget:
                    branchTargets = (int)(sbyte)reader.ReadByte();
                    break;
                case OperandType.InlineBrTarget:
                    branchTargets = reader.ReadInt32();
                    break;
                case OperandType.InlineSwitch:
                    var count = reader.ReadUInt32();
                    if (count > reader.RemainingBytes / 4) return Finish(list, branches);
                    var deltas = new int[count];
                    for (int i = 0; i < count; i++) deltas[i] = reader.ReadInt32();
                    branchTargets = deltas;
                    break;
                case OperandType.ShortInlineI:
                    instr.Operand = op.Code == Code.Ldc_I4_S ? (object)reader.ReadSByte() : reader.ReadByte();
                    break;
                case OperandType.ShortInlineVar:
                    instr.Operand = (int)reader.ReadByte();
                    break;
                case OperandType.InlineVar:
                    instr.Operand = (int)reader.ReadUInt16();
                    break;
                case OperandType.InlineI:
                    instr.Operand = reader.ReadInt32();
                    break;
                case OperandType.InlineI8:
                    instr.Operand = reader.ReadInt64();
                    break;
                case OperandType.ShortInlineR:
                    instr.Operand = reader.ReadSingle();
                    break;
                case OperandType.InlineR:
                    instr.Operand = reader.ReadDouble();
                    break;
                case OperandType.InlineString:
                    instr.Operand = metadata.GetUserString(MetadataTokens.UserStringHandle(reader.ReadInt32() & 0x00FFFFFF));
                    break;
                default: // InlineField / InlineMethod / InlineType / InlineTok / InlineSig: a metadata token
                    instr.Operand = resolve(reader.ReadUInt32());
                    break;
            }
            if (branchTargets != null)
                branches.Add((instr, branchTargets, reader.Offset));
            list.Add(instr);
        }
        return Finish(list, branches);
    }

    private static int OperandSize(OperandType type) => type switch
    {
        OperandType.InlineNone or OperandType.InlinePhi => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        _ => 4,
    };

    private static List<Instruction> Finish(List<Instruction> list, List<(Instruction Instr, object Targets, int Next)> branches)
    {
        if (branches.Count > 0)
        {
            var byOffset = list.ToDictionary(i => i.Offset);
            foreach (var (instr, targets, next) in branches)
            {
                Instruction? At(int delta) => byOffset.GetValueOrDefault((uint)(next + delta));
                instr.Operand = targets is int[] deltas ? deltas.Select(d => At(d)!).ToArray() : At((int)targets);
            }
        }
        return list;
    }
}
