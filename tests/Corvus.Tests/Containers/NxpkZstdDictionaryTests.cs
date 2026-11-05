using System.Buffers.Binary;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>NXPK entries compressed with a Zstandard dictionary held by an executable next to the archive.</summary>
public sealed class NxpkZstdDictionaryTests : IDisposable
{
    private const uint DictionaryId = 4242;
    private readonly string _folder = Directory.CreateTempSubdirectory("nxpk-dict").FullName;

    // A 2,048-byte dictionary built from synthetic text records, id 4242.
    private static readonly byte[] Dictionary = Convert.FromBase64String(
        "N6Qw7JIQAAAhENCSFDr//////w+is/3v7ZPtf6wLVXDIlKRMSdrmqokDIwEAFBKQyyYUey8AAATAgA02YJG5A8AgAgAAAAAAAAAA"+
        "AAAAAAAAAAAAAACka1cbAAAAAAAAAAAAAAAAAAAAAQAAAAQAAAAIAAAAOTEgaW5kZXg2IGNvbmZpZzg5IGRlbHRhMjIgZGVsdGEx"+
        "MCBnYW1tYTYxIGJldGE3MCBnYW1tYTc3IHRhYmxlMjEgdmFsdWU2NSBnYW1tYTQzIGJldGEyMSB0YWJsZTQ4IGluZGV4MzcgcmVj"+
        "b3JkMCBjb25maWc0NSBiZXRhNTggaW5kZXgxNiBnYW1tYTg3IGVudHJ5NTcgcmVjb3JkNzAgZGVsdGE5NyBlbnRyeTExIGJldGE0"+
        "NCBkZWx0YTQgZW50cnk3NiBnYW1tYTY2IGRlbHRhMTMgaW5kZXgyNiBlbnRyeTY0IGFscGhhODJhbHBoYTczIHZhbHVlMjUgZGVs"+
        "dGEzOSBnYW1tYTEyIHJlY29yZDYwIGVudHJ5NzEgZGVsdGE4OSBlbnRyeTI0IGdhbW1hNjQgcmVjb3JkOTMgZ2FtbWE2NCBiZXRh"+
        "MTUgZ2FtbWExNCBiZXRhMzAgZW50cnk0MCB2YWx1ZTYxIGRlbHRhNTQgZ2FtbWE3NCBjb25maWc1MiB2YWx1ZTMzIGRlbHRhMCB2"+
        "YWx1ZTMyIGNvbmZpZzg3IGJldGE1NiBhbHBoYTUyIGRlbHRhOTAgZGVsdGE3MSByZWNvcmQ4NiB2YWx1ZTQ4IGluZGV4MjMgdGFi"+
        "bGU1MiBjb25maWc1MyBhbHBoYTU1IHJlY29yZDUxIGNvbmZpZzU4IGVudHJ5MjggcmVjb3JkZzY3IHZhbHVlNzAgZW50cnk1MSBy"+
        "ZWNvcmQ2MiBpbmRleDIyIGVudHJ5NzAgYWxwaGExIGRlbHRhNzYgdmFsdWU2NCB2YWx1ZTQgcmVjb3JkMjAgdmFsdWU2MCBkZWx0"+
        "YTExIGRlbHRhMzIgdmFsdWU1NCBpbmRleDIzIGNvbmZpZzMwIGFscGhhOTggZ2FtbWE4MyBlbnRyeTY2IGNvbmZpZzg2IHZhbHVl"+
        "MzAgY29uZmlnNjcgZGVsdGEyMSBjb25maWc5MyBjb25maWczNyBhbHBoYTM0IHZhbHVlNDUgYmV0YTk5IGRlbHRhODEgZW50cnk0"+
        "OWRlbHRhODcgcmVjb3JkNTEgZGVsdGE0MyBhbHBoYTY2IGVudHJ5ODEgZGVsdGEyNyB0YWJsZTQgYWxwaGEzMSB2YWx1ZTQ1IGlu"+
        "ZGV4NjkgdGFibGUwIGluZGV4NjMgYmV0YTkyIGNvbmZpZzc2IGJldGE4OSB0YWJsZTEgZ2FtbWEzNyB0YWJsZTExIGdhbW1hMjUg"+
        "dGFibGUyNyBnYW1tYTM0IGJldGEyNiB0YWJsZTggcmVjb3JkNjggZ2FtbWE0OCBlbnRyeTMwIGJldGE4MSB2YWx1ZTk1IHJlY29y"+
        "ZDQgZW50cnk4OSByZWNvcmQzOSB2YWx1ZTcgdmFsdWU1MSBpbmRleDQ5IGdhbW1hMTIgcmVjb3JkNDkgYmV0YTMwIGdhbW1hMTYg"+
        "dmFsdWUzNyBhbHBoYTQ5YWxwaGE4NiBnYW1tYTc0IGdhbW1hNjAgaW5kZXgyMyBhbHBoYTQgYmV0YTQgZGVsdGE4MSB2YWx1ZTkg"+
        "ZW50cnk5NiBjb25maWc1NSBlbnRyeTE3IHJlY29yZDU5IGRlbHRhMjggdmFsdWU4NSBpbmRleDY0IHRhYmxlOTcgYWxwaGE0NSBy"+
        "ZWNvcmQ2NSBkZWx0YTQzIGVudHJ5NDUgYmV0YTMzIGNvbmZpZzcyIHJlY29yZDE4IGdhbW1hMjAgZGVsdGE4MiBlbnRyeTEwIHJl"+
        "Y29yZDc3IGdhbW1hNzggZGVsdGE0MSBpbmRleDQ3IGdhbW1hMSBiZXRhOTMgdGFibGUzMCBpbmRleDI4IGRlbHRhOSBnYW1tYTkg"+
        "aW5kZXgxMiBnYW1tYTQ2IHJlY29yZDk5IGluZGV4NXJlY29yZDM1IGdhbW1hMjggZ2FtbWE0MSBkZWx0YTM3IGNvbmZpZzI4IGVu"+
        "dHJ5NTYgcmVjb3JkNzIgaW5kZXg5MyBlbnRyeTM1IGVudHJ5MyByZWNvcmQ4MiBlbnRyeTY3IGRlbHRhNDMgdmFsdWU5MiByZWNv"+
        "cmQ3OCByZWNvcmQ1IGluZGV4NjkgZW50cnk4OSBjb25maWc1NSBhbHBoYTkyIGFscGhhMTAgYmV0YTYwIHZhbHVlNzYgdmFsdWU5"+
        "NSBiZXRhNyBiZXRhMCB2YWx1ZTIwIGdhbW1hNjMgY29uZmlnODUgYWxwaGE2OSB2YWx1ZTExIGVudHJ5MzEgcmVjb3JkOTkgYWxw"+
        "aGEzNyBiZXRhNzQgY29uZmlnODEgZW50cnk5NSBkZWx0YTk3IGdhbW1hNjEgY29uZmlnNDFkZWx0YTM3IGJldGEyOSB0YWJsZTEz"+
        "IGFscGhhMjggdmFsdWU5OCBjb25maWcxNiBpbmRleDQwIHJlY29yZDIxIGluZGV4OTkgYWxwaGExOCBpbmRleDY0IGluZGV4ODUg"+
        "ZGVsdGE2NSBpbmRleDU1IGNvbmZpZzMzIGRlbHRhOTggZGVsdGEyNCB0YWJsZTkyIGFscGhhMzIgYWxwaGE5NiBpbmRleDYzIGFs"+
        "cGhhNzkgZ2FtbWE5OSB0YWJsZTIgZGU=");

    public void Dispose() { try { Directory.Delete(_folder, true); } catch (IOException) { } }

    private static byte[] Record(int i) =>
        Encoding.ASCII.GetBytes(string.Join(" ", Enumerable.Range(0, 40).Select(k => "alpha" + (i * 7 + k) % 90 + " beta" + (i + k * 3) % 50 + " record" + k)));

    private static byte[] Pack(byte[] raw)
    {
        using var c = new ZstdSharp.Compressor(3);
        c.SetParameter(ZstdSharp.Unsafe.ZSTD_cParameter.ZSTD_c_checksumFlag, 1);
        c.LoadDictionary(Dictionary);
        return c.Wrap(raw).ToArray();
    }

    private static byte[] Archive(byte[][] raws)
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(new byte[24]);
        var packed = raws.Select(Pack).ToArray();
        var at = new List<uint>();
        foreach (var p in packed) { at.Add((uint)ms.Length); w.Write(p); }
        uint index = (uint)ms.Length;
        for (int i = 0; i < raws.Length; i++)
        {
            w.Write((uint)(0xD0 + i));
            w.Write(at[i]);
            w.Write((uint)packed[i].Length);
            w.Write((uint)raws[i].Length);
            w.Write(new byte[12]);
        }
        var data = ms.ToArray();
        "NXPK"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(4), (uint)raws.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), index);
        return data;
    }

    private static byte[] Decoy(uint id, int length)
    {
        var d = new byte[length];
        new Random(5).NextBytes(d);
        new byte[] { 0x37, 0xA4, 0x30, 0xEC }.CopyTo(d, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(4), id);
        return d;
    }

    private string Write(string name, byte[] data)
    {
        var path = Path.Combine(_folder, name);
        File.WriteAllBytes(path, data);
        return path;
    }

    private static byte[] Executable(params byte[][] parts)
    {
        var head = new byte[] { (byte)'M', (byte)'Z', 0, 0 };
        var filler = new byte[300];
        return head.Concat(filler).Concat(parts.SelectMany(p => p.Concat(new byte[37]))).ToArray();
    }

    [Fact]
    public void A_dictionary_in_a_sibling_executable_decodes_the_entries_and_is_named()
    {
        var raws = Enumerable.Range(0, 5).Select(Record).ToArray();
        var archive = Write("data.npk", Archive(raws));
        Write("main.exe", Executable(Decoy(7, 700), Dictionary, Decoy(9, 900)));
        var contents = Containers.Open(File.ReadAllBytes(archive), "data.npk", AnalysisLimits.Default, default, archive, allFiles: true);
        Assert.Equal(raws, contents.Items.OrderBy(i => i.Name, StringComparer.Ordinal).Select(i => i.Bytes));
        Assert.Contains(contents.Notes, n => n.Contains("dictionary 4242 read from main.exe at offset 0x") && n.Contains("2,048 bytes"));
        Assert.DoesNotContain(contents.Notes, n => n.Contains("need a trained dictionary"));
    }

    [Fact]
    public void Without_the_sibling_executable_the_missing_dictionary_message_stays()
    {
        var archive = Write("data.npk", Archive([Record(1), Record(2)]));
        var contents = Containers.Open(File.ReadAllBytes(archive), "data.npk", AnalysisLimits.Default, default, archive, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Contains(contents.Notes, n => n.Contains("need a trained dictionary") && n.Contains("4242 x2"));
    }

    [Fact]
    public void A_decoy_with_the_wanted_id_but_other_bytes_is_not_accepted()
    {
        var archive = Write("data.npk", Archive([Record(1)]));
        Write("main.exe", Executable(Decoy(DictionaryId, 3000)));
        var contents = Containers.Open(File.ReadAllBytes(archive), "data.npk", AnalysisLimits.Default, default, archive, allFiles: true);
        Assert.Empty(contents.Items);
        Assert.Contains(contents.Notes, n => n.Contains("need a trained dictionary"));
    }
}
