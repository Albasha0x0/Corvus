using System.Text;
using Corvus.Native;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Script runtime detection from API names, module names and string markers.</summary>
public sealed class ScriptRuntimeDetectionTests
{
    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    [Fact]
    public void Lua_is_named_with_its_version_and_binding_calls()
    {
        string[] names = ["lua_newstate", "luaL_openlibs", "lua_pushcclosure", "luaL_setfuncs", "memcpy"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, [], Ascii("\0Lua 5.4.6  Copyright (C) 1994-2023\0")));
        Assert.Equal("Lua", found.Name);
        Assert.Equal("5.4.6", found.Version);
        Assert.Equal(["luaL_setfuncs", "lua_pushcclosure"], found.Binding);
    }

    [Fact]
    public void The_first_marker_without_a_version_tail_does_not_hide_a_later_one()
    {
        string[] names = ["lua_newstate", "luaL_openlibs"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, [], Ascii("Lua 5.x\0Lua 5.1.5\0")));
        Assert.Equal("5.1.5", found.Version);
    }

    [Fact]
    public void Luajit_hides_the_lua_match_of_the_same_api()
    {
        string[] names = ["luaJIT_setmode", "lua_newstate", "luaL_openlibs"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, [], Ascii("LuaJIT 2.1.0-beta3")));
        Assert.Equal("LuaJIT", found.Name);
        Assert.Equal("2.1.0", found.Version);
    }

    [Fact]
    public void Luajit_module_without_a_marker_hides_the_lua_match()
    {
        string[] names = ["lua_newstate", "luaL_openlibs"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, ["luajit51.dll"], []));
        Assert.Equal("LuaJIT", found.Name);
    }

    [Fact]
    public void Lua_is_kept_beside_luajit_when_a_lua_marker_is_present()
    {
        string[] names = ["luaJIT_setmode", "lua_newstate", "luaL_openlibs"];
        var found = ScriptRuntimeDetection.Detect(names, [], Ascii("LuaJIT 2.1.0\0Lua 5.1.4\0"));
        Assert.Equal(["LuaJIT", "Lua"], found.Select(f => f.Name));
    }

    [Fact]
    public void Quickjs_is_named_from_its_marker_beside_an_api_name()
    {
        var found = Assert.Single(ScriptRuntimeDetection.Detect(["JS_NewRuntime"], [], Ascii("QuickJS version 2024-01-13")));
        Assert.Equal("QuickJS", found.Name);
        Assert.Contains("1 API name ", found.Evidence);
    }

    [Fact]
    public void A_weak_marker_alone_names_no_runtime()
    {
        Assert.Empty(ScriptRuntimeDetection.Detect([], [], Ascii("QuickJS docs; mruby 3.2; Python 3.11")));
    }

    [Fact]
    public void Spidermonkey_names_are_not_reported_as_quickjs()
    {
        Assert.Empty(ScriptRuntimeDetection.Detect(["JS_EvaluateScript", "JS_NewContext"], [], []));
    }

    [Fact]
    public void V8_binding_calls_match_by_prefix_of_the_mangled_name()
    {
        string[] names = ["?Dispose@Isolate@v8@@QEAAXXZ", "?New@FunctionTemplate@v8@@SA?AV?$Local@VFunctionTemplate@v8@@@2@PEAVIsolate@2@P6AXAEBV?$FunctionCallbackInfo@VValue@v8@@@2@@Z@Z"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, [], []));
        Assert.Equal("V8", found.Name);
        Assert.Single(found.Binding);
        Assert.StartsWith("?New@FunctionTemplate@v8@@", found.Binding[0]);
    }

    [Fact]
    public void Python_version_is_read_beside_its_api_names()
    {
        string[] names = ["Py_Initialize", "PyRun_SimpleString", "PyModule_Create2"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, [], Ascii("Python 3.11.4 (main)")));
        Assert.Equal("3.11.4", found.Version);
        Assert.Equal(["PyModule_Create2"], found.Binding);
    }

    [Fact]
    public void Mruby_version_is_read_beside_its_api_names()
    {
        string[] names = ["mrb_open", "mrb_define_method"];
        var found = Assert.Single(ScriptRuntimeDetection.Detect(names, [], Ascii("mruby 3.2.0")));
        Assert.Equal("3.2.0", found.Version);
        Assert.Equal(["mrb_define_method"], found.Binding);
    }

    [Fact]
    public void Python_is_named_from_its_dependency_module()
    {
        var found = Assert.Single(ScriptRuntimeDetection.Detect([], ["python311.dll", "kernel32.dll"], []));
        Assert.Equal("Python", found.Name);
        Assert.Contains("module python311.dll", found.Evidence);
    }

    [Fact]
    public void A_python_extension_module_is_not_reported_as_an_embedded_runtime()
    {
        Assert.Empty(ScriptRuntimeDetection.Detect(["PyInit_speedups", "PyModule_Create2", "PyArg_ParseTuple"], ["python311.dll"], []));
    }

    [Fact]
    public void A_single_unrelated_prefix_match_names_no_runtime()
    {
        Assert.Empty(ScriptRuntimeDetection.Detect(["mrb_x"], [], Ascii("plain text")));
    }

    [Fact]
    public void Empty_and_truncated_file_bytes_name_no_runtime()
    {
        Assert.Empty(ScriptRuntimeDetection.Detect([], [], []));
        Assert.Empty(ScriptRuntimeDetection.Detect([], [], Ascii("Lua 5.")));
    }

    [Fact]
    public void The_format_summary_line_names_the_runtime_version_and_binding_layer()
    {
        var image = new NamesImage { Exports = [new("lua_newstate", 1, 0x1000, null), new("lua_pushcclosure", 2, 0x1010, null)] };
        var sb = new StringBuilder();
        NativeTools.ScriptRuntimeLines(sb, image, Ascii("Lua 5.4.6"));
        Assert.Equal("Script runtime: Lua 5.4.6: 2 API names (lua_newstate, lua_pushcclosure); string \"Lua 5.\"; binding layer: lua_pushcclosure\n",
            sb.ToString().ReplaceLineEndings("\n"));
    }

    private sealed class NamesImage : INativeImage
    {
        public string Path => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public bool Is64Bit => true;
        public bool IsDll => true;
        public ulong ImageBase => 0;
        public uint EntryPointRva => 0;
        public uint SizeOfImage => 0;
        public IReadOnlyList<NativeSection> Sections => [];
        public IReadOnlyList<NativeImport> Imports { get; init; } = [];
        public IReadOnlyList<NativeExport> Exports { get; init; } = [];
        public IReadOnlyList<RuntimeFunction> RuntimeFunctions => [];
        public IReadOnlyList<uint> RelocationRvas => [];
        public IReadOnlyList<uint> TlsCallbackRvas => [];
        public IReadOnlyList<ParseIssue> Issues => [];
        public int Read(uint rva, Span<byte> destination) => 0;
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) { fileOffset = 0; return false; }
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) { rva = 0; return false; }
        public NativeSection? SectionAt(uint rva) => null;
    }
}
