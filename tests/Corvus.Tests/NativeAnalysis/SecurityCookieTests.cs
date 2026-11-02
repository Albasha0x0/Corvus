using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;
using Corvus.Native.Code;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The security cookie global found from prologues when the load config is absent.</summary>
public sealed class SecurityCookieTests
{
    private const uint CookieRva = 0x3010;

    // Three functions at 0x1000, 0x1020 and 0x1040 that load the global at 0x3010 and xor it with rsp, then return.
    private static byte[] Image(bool withPrologues = true, bool executableCookie = false, bool loadConfig = false, bool x86 = false,
        int functions = 3, bool swappedXor = false, bool badFirstLoad = false)
    {
        var pe = new PeBuilder { EntryPoint = 0x1000, Characteristics = 0x0022 };
        if (x86) { pe.Is64 = false; pe.Machine = 0x14C; }
        var cookie = functions > 100 ? 0x200010u : CookieRva;
        var text = new byte[0x20 * functions];
        for (int i = 0; i < functions; i++)
        {
            int at = i * 0x20;
            if (!withPrologues) { text[at] = 0xC3; continue; }
            // mov rax,[rip+disp32]; xor rax,rsp; ret
            byte[] code = [0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, swappedXor ? (byte)0x31 : (byte)0x33, swappedXor ? (byte)0xE0 : (byte)0xC4, 0xC3];
            BitConverter.GetBytes((int)((executableCookie ? 0x1050 : cookie) - (0x1000 + at + 7))).CopyTo(code, 3);
            code.CopyTo(text, at);
            if (!badFirstLoad) continue;
            // A rejected load of code, then the valid load, in one prologue.
            byte[] two = [0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0x33, 0xC4, 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0x48, 0x33, 0xC4, 0xC3];
            BitConverter.GetBytes((int)(0x1000 - (0x1000 + at + 7))).CopyTo(two, 3);
            BitConverter.GetBytes((int)(cookie - (0x1000 + at + 17))).CopyTo(two, 13);
            two.CopyTo(text, at);
        }
        pe.Sections.Add(new PeBuilder.Section { Name = ".text", Rva = 0x1000, Data = text, Characteristics = 0x6000_0020 });
        var rdataRva = functions > 100 ? 0x100000u : 0x2000u;
        var dataRva = functions > 100 ? 0x200000u : 0x3000u;
        var rdata = new byte[0x300 + 12 * functions];
        // Unwind info: version 1, no prolog, no codes.
        rdata[0] = 1;
        for (int i = 0; i < functions; i++)
        {
            BitConverter.GetBytes((uint)(0x1000 + i * 0x20)).CopyTo(rdata, 4 + i * 12);
            BitConverter.GetBytes((uint)(0x1000 + i * 0x20 + 0x1F)).CopyTo(rdata, 8 + i * 12);
            BitConverter.GetBytes(rdataRva).CopyTo(rdata, 12 + i * 12);
        }
        pe.Sections.Add(new PeBuilder.Section { Name = ".rdata", Rva = rdataRva, Data = rdata, Characteristics = 0x4000_0040 });
        pe.Sections.Add(new PeBuilder.Section { Name = ".data", Rva = dataRva, Data = new byte[0x40], Characteristics = 0xC000_0040 });
        pe.Directories[3] = (rdataRva + 4, (uint)(12 * functions));
        if (loadConfig)
        {
            BitConverter.GetBytes(0x140).CopyTo(rdata, 0x100);
            // SecurityCookie field of the 64-bit load config.
            BitConverter.GetBytes(0x140000000UL + CookieRva).CopyTo(rdata, 0x100 + 88);
            pe.Directories[10] = (rdataRva + 0x100, 0x140);
        }
        return pe.Build();
    }

    [Fact]
    public void A_prologue_load_xored_with_rsp_identifies_the_cookie_without_a_load_config()
    {
        var pe = PeFile.FromBytes(Image());
        Assert.Null(pe.LoadConfig);
        Assert.Equal(CookieRva, pe.CodeSecurityCookieRva);
        var (on, off) = PeDescribe.Mitigations(pe);
        Assert.Contains("GS cookie (used by code, load config absent)", on);
        Assert.DoesNotContain("GS cookie", off);
    }

    [Fact]
    public void An_image_without_the_prologue_reports_the_cookie_off()
    {
        var pe = PeFile.FromBytes(Image(withPrologues: false));
        Assert.Null(pe.CodeSecurityCookieRva);
        Assert.Contains("GS cookie", PeDescribe.Mitigations(pe).Off);
    }

    [Fact]
    public void A_load_target_in_executable_code_is_not_a_cookie()
    {
        Assert.Null(PeFile.FromBytes(Image(executableCookie: true)).CodeSecurityCookieRva);
    }

    [Fact]
    public void The_code_index_names_the_cookie_global()
    {
        var pe = PeFile.FromBytes(Image());
        var index = NativeCodeIndex.Build(pe);
        Assert.Equal(NativeCodeIndex.SecurityCookieName, index.NameAt(CookieRva));
        Assert.Null(index.NameAt(CookieRva + 8));
    }

    [Fact]
    public void The_load_config_names_the_cookie_without_prologues()
    {
        var pe = PeFile.FromBytes(Image(withPrologues: false, loadConfig: true));
        Assert.NotNull(pe.LoadConfig);
        Assert.Equal(CookieRva, pe.LoadConfigSecurityCookieRva);
        Assert.Equal(NativeCodeIndex.SecurityCookieName, NativeCodeIndex.Build(pe).NameAt(CookieRva));
        Assert.Contains("GS cookie", PeDescribe.Mitigations(pe).On);
    }

    [Fact]
    public void A_rejected_load_does_not_hide_a_later_valid_one_in_the_prologue()
    {
        Assert.Equal(CookieRva, PeFile.FromBytes(Image(badFirstLoad: true)).CodeSecurityCookieRva);
    }

    [Fact]
    public void The_xor_with_the_operands_swapped_identifies_the_cookie()
    {
        Assert.Equal(CookieRva, PeFile.FromBytes(Image(swappedXor: true)).CodeSecurityCookieRva);
    }

    [Fact]
    public void A_single_sampled_function_identifies_the_cookie()
    {
        var one = Image(functions: 1);
        Assert.Equal(CookieRva, PeFile.FromBytes(one).CodeSecurityCookieRva);
    }

    [Fact]
    public void An_x86_image_has_no_code_cookie()
    {
        Assert.Null(PeFile.FromBytes(Image(x86: true)).CodeSecurityCookieRva);
    }

    [Fact]
    public void A_table_over_the_sample_limit_is_read_at_a_stride()
    {
        var pe = PeFile.FromBytes(Image(functions: 4100));
        Assert.Equal(0x200010u, pe.CodeSecurityCookieRva);
    }

    [Fact]
    public async Task A_user_name_wins_over_the_cookie_name()
    {
        using var dir = new TempDir();
        var path = dir.File("cookie.exe");
        File.WriteAllBytes(path, Image());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var edit = new NativeEditTools(h.Workspace, h.Code, new NativeEditService(h.Workspace, h.Code));
        await edit.RenameNative(path, $"rva:0x{CookieRva:X}", "user_cookie", dryRun: false);
        var listing = await h.CodeTools.Disassemble(path, "rva:0x1000");
        Assert.Contains("user_cookie", listing);
        Assert.DoesNotContain("__security_cookie", listing);
    }

    [Fact]
    public async Task Disassemble_names_the_cookie_operand()
    {
        using var dir = new TempDir();
        var path = dir.File("cookie.exe");
        File.WriteAllBytes(path, Image());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        Assert.Contains("__security_cookie", await h.CodeTools.Disassemble(path, "rva:0x1000"));
    }

    [Fact]
    public async Task Get_pe_info_and_summarize_file_report_the_cookie_used_by_code()
    {
        using var dir = new TempDir();
        var path = dir.File("cookie.exe");
        File.WriteAllBytes(path, Image());
        using var h = new NativeToolHarness(backgroundIndexing: false);
        Assert.Contains("GS cookie (used by code, load config absent)", await h.Native.GetPeInfo(path));
        var summary = new InspectionService(new Core.AssemblyWorkspace(new Core.ServerOptions())).Summarize(null, path, CancellationToken.None);
        Assert.Contains(summary.Highlights, l => l.Contains("GS cookie (used by code", StringComparison.Ordinal));
    }
}
