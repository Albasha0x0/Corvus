using Corvus.Core.WebAssembly;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>GC-proposal modules: recursion groups, sub types, struct and array types, typed references, read, written as WAT and validated.</summary>
public sealed class WasmGcTests(ITestOutputHelper output)
{
    // (rec (type $Node (sub (struct (field i32) (field (mut (ref null $Node))))))
    //      (type $Leaf (sub final $Node (struct (field i32) (field (mut (ref null $Node))) (field i8)))))
    private static readonly byte[] Group =
    [
        0x4E, 2,
        0x50, 0, 0x5F, 2, 0x7F, 0, 0x63, 0, 1,
        0x4F, 1, 0, 0x5F, 3, 0x7F, 0, 0x63, 0, 1, 0x78, 0,
    ];

    /// <summary>
    /// Types 0-1 the group above, 2 (array (mut i8)), 3 (func (param (ref null 0)) (result i32)), 4 (func (result (ref 2)));
    /// a field read after ref.test and ref.as_non_null, an array.new_default, a br_on_cast to a typed block, a global
    /// built by array.new_fixed.
    /// </summary>
    internal static byte[] Module(Action<WasmModuleBuilder>? more = null)
    {
        var b = new WasmModuleBuilder();
        b.RawType(Group);
        b.RawType(0x5E, 0x78, 1);
        b.RawType(0x60, 1, 0x63, 0, 1, 0x7F);
        b.RawType(0x60, 0, 1, 0x64, 2);
        b.FuncRawLocals(3, [0], [0x20, 0, 0xFB, 20, 1, 0x1A, 0x20, 0, 0xD4, 0xFB, 2, 0, 0]);
        b.FuncRawLocals(4, [0], [0x41, 4, 0xFB, 7, 2]);
        b.FuncRawLocals(3, [0],
        [
            0x02, 0x64, 1, // block (result (ref 1))
            0x20, 0, 0xFB, 24, 1, 0, 0, 1, // br_on_cast 0 (ref null 0) (ref 1)
            0x1A, 0x41, 0, 0x0F, 0x0B,
            0xFB, 4, 1, 2, // struct.get_u 1 2
        ]);
        b.GlobalRaw([0x64, 2], false, [0x41, 1, 0x41, 2, 0xFB, 8, 2, 2]);
        more?.Invoke(b);
        return b.Build();
    }

    [Fact]
    public void Gc_module_is_read_written_as_wat_and_valid()
    {
        var m = WasmBinary.Read(Module());
        Assert.Empty(m.Issues);
        Assert.Null(m.Unsupported);
        Assert.True(m.Gc);
        Assert.Equal([WasmComposite.Struct, WasmComposite.Struct, WasmComposite.Array, WasmComposite.Func, WasmComposite.Func], m.TypeDefs.Select(d => d.Kind));
        Assert.Equal((0, 2, false), (m.TypeDefs[1].Group, m.TypeDefs[1].GroupSize, m.TypeDefs[0].Final));
        Assert.Equal([0u], m.TypeDefs[1].Supers);

        var wat = WatWriter.Module(m)!;
        output.WriteLine(wat);
        Assert.Contains("""
              (rec
                (type (;0;) (sub (struct (field i32) (field (mut (ref null 0))))))
                (type (;1;) (sub final 0 (struct (field i32) (field (mut (ref null 0))) (field i8)))))
              (type (;2;) (array (mut i8)))
              (type (;3;) (func (param (ref null 0)) (result i32)))
              (type (;4;) (func (result (ref 2))))
            """.Replace("\r\n", "\n"), wat);
        Assert.Contains("ref.test (ref 1)\n", wat);
        Assert.Contains("ref.as_non_null\n    struct.get 0 0)\n", wat);
        Assert.Contains("array.new_default 2)\n", wat);
        Assert.Contains("block (result (ref 1))  ;; label = @1\n", wat);
        Assert.Contains("br_on_cast 0 (;@1;) (ref null 0) (ref 1)\n", wat);
        Assert.Contains("struct.get_u 1 2)\n", wat);
        Assert.Contains("(global (;0;) (ref 2) (array.new_fixed 2 2\n      (i32.const 1)\n      (i32.const 2))))", wat);

        var v = WasmValidator.Validate(m);
        Assert.True(v.Valid, string.Join("; ", v.Errors));
        var lifted = WasmDecompiler.Function(m, 1, i => $"f{i}");
        output.WriteLine(lifted);
        Assert.Contains("new type_2[4]", lifted);
    }

    [Fact]
    public void Gc_rules_are_checked()
    {
        string Error(Action<WasmModuleBuilder> more)
        {
            var v = WasmValidator.Validate(WasmBinary.Read(Module(more)));
            Assert.Equal("invalid", v.Verdict);
            return Assert.Single(v.Errors);
        }
        // struct.set on the immutable field 0
        Assert.Contains("struct.set: field 0 of type 0 is immutable", Error(b => b.FuncRawLocals(3, [0], [0x20, 0, 0x41, 1, 0xFB, 5, 0, 0, 0x41, 0])));
        // a sub type of the final type 1
        Assert.Contains("supertype 1 is final", Error(b => b.RawType(0x50, 1, 1, 0x5F, 3, 0x7F, 0, 0x63, 0, 1, 0x78, 0)));
        // a non-nullable local read before it is set
        Assert.Contains("local 1 ((ref 0)) is read before it is set", Error(b => b.FuncRawLocals(3, [1, 1, 0x64, 0], [0x20, 1, 0xFB, 2, 0, 0])));
        // array.get of a packed array without _s / _u
        Assert.Contains("array.get: a packed field is read with _s or _u", Error(b => b.FuncRawLocals(4, [0], [0x41, 1, 0xFB, 7, 2, 0x41, 0, 0xFB, 11, 2, 0x1A, 0x41, 1, 0xFB, 7, 2])));
        // a struct where a (ref 2) array is expected
        Assert.Contains("type mismatch: expected (ref 2), got (ref 0)", Error(b => b.FuncRawLocals(4, [0], [0x41, 1, 0xD0, 0x71, 0xFB, 0, 0])));
    }
}
