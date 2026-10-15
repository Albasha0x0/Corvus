using System.Globalization;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// The initial data of a FieldRVA field (array initializers, UTF-8 literals, static spans): where it is in the file, its
/// bytes and hash, the methods that read it and, from the newarr / span creation beside each read, the element type
/// that decodes it.
/// </summary>
public static class FieldInitialData
{
    /// <summary>A method that loads the field (ldtoken, ldsflda, ldsfld) at an IL offset, with the element type found beside it.</summary>
    public sealed record Use(MethodDef Method, int ILOffset, TypeSig? Element);

    /// <param name="FileOffset">Null when the RVA lies in no section.</param>
    /// <param name="Verified">The bytes at the file offset equal the data the metadata declares.</param>
    public sealed record Data(uint Rva, long? FileOffset, bool Verified, byte[] Bytes, string Sha256, IReadOnlyList<Use> Uses, int UsesTotal);

    private const int MaxUses = 20;

    /// <summary>The data of <paramref name="field"/>, or null when it has none.</summary>
    public static Data? Of(LoadedAssembly asm, FieldDef field, CancellationToken ct)
    {
        if (!field.HasFieldRVA || MetadataUtil.Try(() => field.InitialValue) is not { } bytes) return null;
        uint rva = (uint)field.RVA;
        long? fileOffset = null;
        bool verified = false;
        long at = 0;
        try { at = rva != 0 ? (long)asm.Module.Metadata.PEImage.ToFileOffset(field.RVA) : 0; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IndexOutOfRangeException) { }
        if (at > 0)
        {
            fileOffset = at;
            var file = asm.OriginalBytes;
            verified = at + bytes.Length <= file.Length && file.AsSpan((int)at, bytes.Length).SequenceEqual(bytes);
        }
        var uses = new List<Use>();
        int total = 0;
        foreach (var type in asm.Module.GetTypes())
            foreach (var method in type.Methods)
            {
                ct.ThrowIfCancellationRequested();
                if (!method.HasBody && method.RVA == 0) continue;
                List<Instruction>? il = null;
                int index = -1;
                foreach (var instr in FastIlReader.Instructions(asm, method))
                {
                    index++;
                    if (instr.OpCode.Code is not (Code.Ldtoken or Code.Ldsflda or Code.Ldsfld) || MetadataUtil.AsField(instr.Operand) is not { } f
                        || !ReferenceEquals(MetadataUtil.Try(() => f.ResolveFieldDef()), field)) continue;
                    if (++total > MaxUses) continue;
                    il ??= FastIlReader.Instructions(asm, method).ToList();
                    uses.Add(new Use(method, (int)instr.Offset, SearchService.ElementTypeAround(il, index)));
                }
            }
        return new Data(rva, fileOffset, verified, bytes, Convert.ToHexStringLower(SHA256.HashData(bytes)), uses, total);
    }

    /// <summary>
    /// The first <paramref name="max"/> elements of the data as <paramref name="element"/> (a primitive, or an enum by
    /// member name), or null for other types; <paramref name="count"/> is the element count.
    /// </summary>
    public static List<string>? Elements(byte[] data, TypeSig? element, int max, out int count)
    {
        count = 0;
        var e = element?.ToTypeDefOrRef() is { } r && MetadataUtil.Try(r.ResolveTypeDef) is { IsEnum: true } en ? en : null;
        var primitive = e != null ? MetadataUtil.Try(e.GetEnumUnderlyingType) : element;
        if (SearchService.ElementSize(primitive) is not { } size || data.Length % size != 0) return null;
        count = data.Length / size;
        var items = new List<string>();
        for (int i = 0; i + size <= data.Length && items.Count < max; i += size)
        {
            var s = data.AsSpan(i, size);
            if (e != null)
            {
                long v = size switch { 1 => primitive!.ElementType == ElementType.I1 ? (sbyte)s[0] : s[0], 2 => BitConverter.ToInt16(s), 4 => BitConverter.ToInt32(s), _ => BitConverter.ToInt64(s) };
                var name = e.Fields.FirstOrDefault(f => f.IsLiteral && f.Constant?.Value is { } c && Convert.ToInt64(c, CultureInfo.InvariantCulture) == v)?.Name.String;
                items.Add(name != null ? $"{e.Name}.{name}" : $"({e.Name}){v}");
                continue;
            }
            items.Add(primitive!.ElementType switch
            {
                ElementType.Boolean => s[0] != 0 ? "true" : "false",
                ElementType.U1 => s[0].ToString(CultureInfo.InvariantCulture),
                ElementType.I1 => ((sbyte)s[0]).ToString(CultureInfo.InvariantCulture),
                ElementType.Char => Format.Literal(BitConverter.ToChar(s)),
                ElementType.U2 => BitConverter.ToUInt16(s).ToString(CultureInfo.InvariantCulture),
                ElementType.I2 => BitConverter.ToInt16(s).ToString(CultureInfo.InvariantCulture),
                // Unsigned tables (CRC, S-boxes, round constants) read best in hex.
                ElementType.U4 => "0x" + BitConverter.ToUInt32(s).ToString("X8", CultureInfo.InvariantCulture),
                ElementType.I4 => BitConverter.ToInt32(s).ToString(CultureInfo.InvariantCulture),
                ElementType.U8 => "0x" + BitConverter.ToUInt64(s).ToString("X16", CultureInfo.InvariantCulture),
                ElementType.I8 => BitConverter.ToInt64(s).ToString(CultureInfo.InvariantCulture),
                ElementType.R4 => BitConverter.ToSingle(s).ToString("R", CultureInfo.InvariantCulture),
                _ => BitConverter.ToDouble(s).ToString("R", CultureInfo.InvariantCulture),
            });
        }
        return items;
    }

    /// <summary>One hex dump row: 16 bytes from <paramref name="at"/> and their ASCII.</summary>
    public static string Row(byte[] data, int at)
    {
        var s = data.AsSpan(at, Math.Min(16, data.Length - at));
        var hex = string.Join(' ', s.ToArray().Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
        var ascii = new string(s.ToArray().Select(b => b is >= 0x20 and < 0x7F ? (char)b : '.').ToArray());
        return $"{hex,-47}  {ascii}";
    }
}
