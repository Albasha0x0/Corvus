using Corvus.Native.Pe;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>
/// find_xrefs keeps .pdata, CFG and export-table references apart from
/// code references.
/// </summary>
public sealed class NativeMetadataXrefTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly Env _env;
    private readonly NativeCodeTools _tools;
    private readonly string _image;
    private readonly uint _f;
    private readonly string _target;

    /// <summary>
    /// Builds an image where f is named by .pdata, a CFG entry and an export;
    /// g calls f.
    /// </summary>
    public NativeMetadataXrefTests()
    {
        var b = new PeBuilder();
        var text = b.Add(".text", new byte[0x40], 0x60000020);
        var code = new byte[0x40];
        code[0] = 0xC3;
        code[0x10] = 0xE8;
        BitConverter.GetBytes(-0x15).CopyTo(code, 0x11);
        code[0x15] = 0xC3;
        text.Data = code;
        b.EntryPoint = text.Rva;
        uint f = text.Rva;
        _f = f;
        _target = $"rva:0x{f:X}";
        var dirs = b.Directories;
        b.Add(".rdata", rva =>
        {
            // Layout: UNWIND_INFO stub, then RUNTIME_FUNCTION rows of 12 bytes.
            var blob = new PeBlob(rva);
            uint unwind = blob.U32(1);
            uint pdata = blob.U32(f);
            blob.U32(f + 1);
            blob.U32(unwind);
            blob.U32(f + 0x10);
            blob.U32(f + 0x16);
            blob.U32(unwind);
            dirs[PeDirectory.Exception] = (pdata, 24);

            blob.Align(4);
            uint exports = blob.Zero(40);
            uint dll = blob.Ascii("meta.dll");
            uint name = blob.Ascii("Alpha");
            blob.Align(4);
            uint eat = blob.U32(f);
            uint names = blob.U32(name);
            uint ordinals = blob.U16(0);
            blob.Patch32(exports + 12, dll);
            blob.Patch32(exports + 16, 1);
            blob.Patch32(exports + 20, 1);
            blob.Patch32(exports + 24, 1);
            blob.Patch32(exports + 28, eat);
            blob.Patch32(exports + 32, names);
            blob.Patch32(exports + 36, ordinals);
            dirs[PeDirectory.Export] = (exports, blob.Here - exports);

            // Offsets 128, 136 and 144 are the x64 IMAGE_LOAD_CONFIG_DIRECTORY
            // GuardCFFunctionTable, GuardCFFunctionCount and GuardFlags fields.
            blob.Align(8);
            uint lcSize = 0x140;
            uint lc = blob.Zero((int)lcSize);
            uint cf = blob.U32(f);
            blob.Bytes([0]);
            void Pointer(uint at, ulong v)
            {
                blob.Patch32(lc + at, (uint)v);
                blob.Patch32(lc + at + 4, (uint)(v >> 32));
            }
            blob.Patch32(lc, lcSize);
            Pointer(128, b.ImageBase + cf);
            Pointer(136, 1);
            blob.Patch32(lc + 144, 0x10000500);
            dirs[PeDirectory.LoadConfig] = (lc, lcSize);
            return blob.ToArray();
        });
        _image = _dir.File("meta.dll");
        File.WriteAllBytes(_image, b.Build());
        _env = new Env();
        _env.Workspace.LoadAny(_image);
        _tools = new NativeCodeTools(_env.Workspace, new Corvus.Services.NativeCodeService(_env.Workspace, _env.Options), _env.Pager);
    }

    // The call site of g is at +0x10 in .text; rows print the VA, then the kind.
    private string CallerRow => $"{_f + 0x10:X}  Call ";

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task Metadata_references_list_pdata_cfg_and_export_rows_without_code_rows()
    {
        var text = await _tools.FindXrefs(_image, _target, kind: "metadata");

        Assert.Contains(".pdata RUNTIME_FUNCTION begin", text);
        Assert.Contains("Control Flow Guard function table", text);
        Assert.Contains("export address table (ordinal 1)", text);
        Assert.DoesNotContain("  Call ", text);
        Assert.DoesNotContain(CallerRow, text);
    }

    [Fact]
    public async Task Default_references_count_metadata_rows_and_list_only_code_rows()
    {
        var text = await _tools.FindXrefs(_image, _target);

        Assert.Contains("+3 metadata references", text);
        Assert.Contains(CallerRow, text);
        Assert.DoesNotContain("RUNTIME_FUNCTION", text);
        Assert.DoesNotContain("export address table", text);
    }

    [Fact]
    public async Task Code_references_exclude_metadata_rows_and_the_metadata_count()
    {
        var text = await _tools.FindXrefs(_image, _target, kind: "code");

        Assert.Contains(CallerRow, text);
        Assert.DoesNotContain("metadata reference", text);
        Assert.DoesNotContain("RUNTIME_FUNCTION", text);
        Assert.DoesNotContain("Control Flow Guard", text);
        Assert.DoesNotContain("export address table", text);
    }
}
