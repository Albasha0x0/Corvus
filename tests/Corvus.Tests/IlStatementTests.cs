using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// IL offsets mapped to C# statements: decompiler sequence points of a method (an async method's MoveNext through the
/// method that starts it), used by Mono frames of crash text and of the Mono runtime's report beside a Unity dump.
/// </summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class IlStatementTests : IDisposable
{
    private const string Source = """
        using System;
        using System.Threading.Tasks;

        namespace Game
        {
            public class Player
            {
                private int _health = 10;

                public void Update()
                {
                    int damage = Damage(3);
                    _health -= damage;
                    if (_health < 0) Die(damage);
                }

                public async Task<int> LoadAsync(int id)
                {
                    await Task.Yield();
                    return Damage(id) + 1;
                }

                private static int Damage(int level) => level * 2;
                private void Die(int last) => throw new InvalidOperationException("dead " + last);
            }
        }
        """;

    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _ws = new();
    private readonly DecompilerService _decompiler;
    private readonly LoadedAssembly _game;

    public IlStatementTests()
    {
        var path = _dir.File("Assembly-CSharp.dll");
        File.WriteAllBytes(path, Roslyn.Release("Assembly-CSharp", Source));
        _game = _ws.Load(path);
        _decompiler = new DecompilerService(_ws, new ServerOptions());
    }

    public void Dispose()
    {
        _ws.Dispose();
        _dir.Dispose();
    }

    private MethodDef Method(string type, string name) => _game.Module.Find(type, true)!.Methods.Single(m => m.Name == name);

    /// <summary>The IL offset of the call to <paramref name="callee"/> in <paramref name="method"/>.</summary>
    private static int CallTo(MethodDef method, string callee) =>
        (int)method.Body.Instructions.First(i => i.OpCode.FlowControl == FlowControl.Call && i.Operand is IMethod m && m.Name == callee).Offset;

    [Fact]
    public void OffsetsMapToTheirStatement()
    {
        var update = Method("Game.Player", "Update");
        var damage = _decompiler.StatementAt(_game, update, CallTo(update, "Damage"), default)!;
        Assert.Equal("int num = Damage(3);", damage.Text); // a release build keeps no local names
        Assert.True(damage.IlStart <= CallTo(update, "Damage") && CallTo(update, "Damage") < damage.IlEnd);
        Assert.Equal("Die(num);", _decompiler.StatementAt(_game, update, CallTo(update, "Die"), default)!.Text);
        Assert.True(damage.Line < _decompiler.StatementAt(_game, update, CallTo(update, "Die"), default)!.Line);
        Assert.Null(_decompiler.StatementAt(_game, update, 0x7FFF, default));
    }

    [Fact]
    public void AsyncMoveNextMapsThroughItsMethod()
    {
        var machine = _game.Module.Find("Game.Player", true)!.NestedTypes.Single(t => t.Name.String.Contains("LoadAsync", StringComparison.Ordinal));
        var moveNext = machine.Methods.Single(m => m.Name == "MoveNext");
        var s = _decompiler.StatementAt(_game, moveNext, CallTo(moveNext, "Damage"), default);
        Assert.Equal("return Damage(id) + 1;", s?.Text);
    }

    [Fact]
    public async Task MonoCrashTextGetsTheStatement()
    {
        var update = Method("Game.Player", "Update");
        var service = new StackTextService(_ws, decompiler: _decompiler);
        var r = await service.Symbolize($"""
            InvalidOperationException: dead 6
              at Game.Player.Update () [0x{CallTo(update, "Die"):x5}] in <{_game.Module.Mvid:N}>:0
              at Game.Player.Update () [0x{CallTo(update, "Die"):x5}] in <{Guid.NewGuid():N}>:0
            """, null, "auto", null, null, 0, 50, default);
        Assert.Equal("Die(num);", r.Frames[0].Statement);
        Assert.Null(r.Frames[1].Statement); // another build: its IL offsets do not apply
    }

    /// <summary>A Unity Mono crash folder: the dump, Player.log with the managed exception and error.log naming JIT code addresses.</summary>
    [Fact]
    public async Task MonoDumpReadsTheRuntimesReportBesideIt()
    {
        var update = Method("Game.Player", "Update");
        var folder = Directory.CreateDirectory(_dir.File("Crash_2026-10-11")).FullName;
        var b = SyntheticCrash.Builder();
        b.Modules.Add(new MinidumpBuilder.Module(0x7FF7_0000_0000, 0x10000, 0x5F000000, @"C:\Game\MonoBleedingEdge\EmbedRuntime\mono-2.0-bdwgc.dll"));
        b.Threads.Clear();
        b.Threads.Add(new MinidumpBuilder.Thread(103, SyntheticCrash.Stack, MinidumpBuilder.ContextX64(SyntheticCrash.JitCode, SyntheticCrash.Stack, rbp: SyntheticCrash.Stack + 0x50)));
        b.Exception = null;
        var dump = Path.Combine(folder, "crash.dmp");
        File.WriteAllBytes(dump, b.Build());
        File.WriteAllText(Path.Combine(folder, "Player.log"), $"""
            Initialize engine version: 2022.3.0f1
            InvalidOperationException: dead 6
              at Game.Player.Update () [0x{CallTo(update, "Die"):x5}] in <{_game.Module.Mvid:N}>:0
            """);
        File.WriteAllText(Path.Combine(folder, "error.log"), $"""
            ========== OUTPUTTING STACK TRACE ==================
            0x{SyntheticCrash.JitCode:X16} (Mono JIT Code) [Player.cs:14] Game.Player:Update ()
            ========== END OF STACKTRACE ===========
            """);
        var service = new MinidumpService(_ws, decompiler: _decompiler, stacks: new StackTextService(_ws, decompiler: _decompiler));

        var m = (await service.Summarize(dump, null, 0, 50, 0, 50, default)).Managed!;
        Assert.Equal("Mono", m.Runtime);
        Assert.Equal("unsupported_runtime", m.Dac.Status);
        Assert.Equal(("InvalidOperationException", "dead 6"), (m.Exception!.Type, m.Exception.Message));
        var frame = Assert.Single(m.Exception.Stack);
        Assert.Equal((_game.Id, "match", "Die(num);"), (frame.Assembly, frame.BuildCheck, frame.Statement));
        Assert.Contains(m.Notes, n => n.Contains("Player.log beside the dump", StringComparison.Ordinal));

        var stack = await service.Stack(dump, null, true, 16, 0, 16, null, default);
        var top = stack.Frames[0];
        Assert.Equal(("mono_log", "managed", _game.Id), (top.SymbolSource, top.Kind, top.Assembly));
        Assert.Contains("Update", top.Function);
        Assert.Contains("error.log", top.Note);
    }
}
