using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Executables with a named RCDATA entry or runtime names in data.</summary>
public sealed class AutoHotkeyScriptTests
{
    // A resource tree with one RCDATA entry under a string name, at fixed offsets from the section start.
    private static byte[] NamedResource(uint rva, string name, byte[] data, uint dataShift = 0)
    {
        var nameBytes = Encoding.Unicode.GetBytes(name);
        uint dataAt = (uint)(0x80 + 2 + nameBytes.Length + 3) & ~3u;
        var t = new byte[dataAt + data.Length];
        void U16(int at, int v) => BitConverter.TryWriteBytes(t.AsSpan(at), (ushort)v);
        void U32(int at, uint v) => BitConverter.TryWriteBytes(t.AsSpan(at), v);
        U16(14, 1);
        U32(16, 10);
        U32(20, 0x80000020);
        U16(0x20 + 12, 1);
        U32(0x30, 0x80000080);
        U32(0x34, 0x80000040);
        U16(0x40 + 14, 1);
        U32(0x50, 1033);
        U32(0x54, 0x60);
        U32(0x60, rva + dataAt + dataShift);
        U32(0x64, (uint)data.Length);
        U16(0x80, name.Length);
        nameBytes.CopyTo(t, 0x82);
        data.CopyTo(t, dataAt);
        return t;
    }

    private static byte[] Executable(byte[] script, string name = ">AUTOHOTKEY SCRIPT<", uint dataShift = 0)
    {
        var pe = new PeBuilder();
        var rsrc = pe.Add(".rsrc", rva => NamedResource(rva, name, script, dataShift));
        pe.Directories[2] = (rsrc.Rva, (uint)rsrc.Data.Length);
        return pe.Build();
    }

    [Fact]
    public void A_script_resource_is_opened_as_the_member_script_ahk()
    {
        var c = Containers.Open(Executable("MsgBox, ledger total`nExitApp\n"u8.ToArray()), "ledger.exe", AnalysisLimits.Default, default);
        Assert.Equal(AutoHotkeyScript.Kind, c.Kind);
        Assert.Equal("MsgBox, ledger total`nExitApp\n", Encoding.UTF8.GetString(c.Items.Single(i => i.Name == "script.ahk").Bytes));
        Assert.StartsWith("AutoHotkey compiled script: resource >AUTOHOTKEY SCRIPT< (", c.Notes[0], StringComparison.Ordinal);
    }


    [Fact]
    public void Two_nim_runtime_names_are_reported_together()
    {
        var pe = new PeBuilder();
        pe.Add(".rdata", Encoding.ASCII.GetBytes("\0NimMainInner\0nimGC_setStackBottom\0"));
        var text = string.Join(" ", NativeEmbeddedContent.Highlights("sample.exe", pe.Build(), default));
        Assert.Contains("Nim runtime names found: NimMainInner, nimGC_setStackBottom.", text, StringComparison.Ordinal);
    }

    [Fact]
    public void One_nim_runtime_name_is_not_reported()
    {
        var pe = new PeBuilder();
        pe.Add(".rdata", Encoding.ASCII.GetBytes("\0NimMainInner\0"));
        var text = string.Join(" ", NativeEmbeddedContent.Highlights("sample.exe", pe.Build(), default));
        Assert.DoesNotContain("Nim", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_overview_names_the_script_resource()
    {
        var text = string.Join(" ", NativeEmbeddedContent.Highlights("sample.exe", Executable("ExitApp"u8.ToArray()), default));
        Assert.Contains("Script container: AutoHotkey compiled script, resource >AUTOHOTKEY SCRIPT<; unpack_container reads the script.", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_script_over_the_item_limit_is_listed_and_not_read()
    {
        var limits = new AnalysisLimits { MaxItemBytes = 4 };
        var c = Containers.Open(Executable("ExitApp"u8.ToArray()), "ledger.exe", limits, default);
        Assert.Empty(c.Items);
        Assert.Equal("script.ahk", c.Entries!.Single().Path);
        Assert.Contains(AnalysisLimits.RaiseVariable, string.Join(" ", c.Notes), StringComparison.Ordinal);
    }

    [Fact]
    public void A_script_with_a_NUL_byte_is_kept_and_noted()
    {
        var c = Containers.Open(Executable([0x41, 0x00, 0x42]), "ledger.exe", AnalysisLimits.Default, default);
        Assert.Equal([0x41, 0x00, 0x42], c.Items.Single().Bytes);
        Assert.Contains("contain NUL", c.Notes[0], StringComparison.Ordinal);
    }

    [Fact]
    public void A_utf16_script_is_not_noted_as_containing_NUL()
    {
        var c = Containers.Open(Executable([0xFF, 0xFE, 0x41, 0x00]), "ledger.exe", AnalysisLimits.Default, default);
        Assert.DoesNotContain("NUL", c.Notes[0], StringComparison.Ordinal);
    }

    [Fact]
    public void A_resource_outside_the_image_is_reported_as_unknown()
    {
        var c = Containers.Open(Executable("ExitApp"u8.ToArray(), dataShift: 0x100000), "ledger.exe", AnalysisLimits.Default, default);
        Assert.Empty(c.Items);
        Assert.Contains("unknown", c.Notes[0], StringComparison.Ordinal);
    }

    [Fact]
    public void An_RCDATA_resource_under_another_name_is_not_a_script()
    {
        Assert.Null(AutoHotkeyScript.Find(Executable("ExitApp"u8.ToArray(), "OTHER")));
        Assert.Null(AutoHotkeyScript.Open(new PeBuilder().Build(), AnalysisLimits.Default));
    }

    [Fact]
    [FuzzEntry(typeof(AutoHotkeyScript))]
    public void Fuzzed_compiled_scripts_never_throw_unexpectedly()
    {
        var failures = FormatFuzz.Run(Executable("MsgBox, ledger total`nExitApp\n"u8.ToArray()), b => AutoHotkeyScript.Open(b, AnalysisLimits.Default), 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
