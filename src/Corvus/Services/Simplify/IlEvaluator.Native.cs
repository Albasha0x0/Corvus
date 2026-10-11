using dnlib.DotNet;
using dnlib.DotNet.MD;

namespace Corvus.Services.Simplify;

internal sealed partial class IlEvaluator
{
    private readonly Dictionary<MethodDef, byte[]> _nativeCode = new();

    /// <summary>
    /// A native method of the module (no P/Invoke import): static, int32 / uint32 parameters and result, x86 code of a
    /// 32-bit image (the code runs as 32-bit code only there), run by <see cref="NativeRoutine"/> within the budget.
    /// </summary>
    private object? RunNative(MethodDef method, object?[] args)
    {
        if (method.ImplMap != null || !method.IsStatic || !method.IsUnmanaged)
            throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)}, native code that is not a static method of the module");
        if (module is not ModuleDefMD md || !md.IsI386 || !(md.Is32BitRequired || md.Is32BitPreferred))
            throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)}, native code of an image that does not run as a 32-bit x86 process");
        var sig = method.MethodSig;
        if (sig.RetType.RemovePinnedAndModifiers().ElementType is not (ElementType.I4 or ElementType.U4) ||
            sig.Params.Any(p => p.RemovePinnedAndModifiers().ElementType is not (ElementType.I4 or ElementType.U4)) || args.Length > 8)
            throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)}, native code with parameters or a result other than 32-bit integers");
        var values = new int[args.Length];
        for (int i = 0; i < args.Length; i++)
            values[i] = args[i] is int v ? v : throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)} with an argument that is not a known integer");
        if (!_nativeCode.TryGetValue(method, out var code))
        {
            if (method.RVA == 0) throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)}, native code with no body in the image");
            try
            {
                var reader = md.Metadata.PEImage.CreateReader(method.RVA);
                code = reader.ReadBytes((int)Math.Min(reader.BytesLeft, (uint)NativeRoutine.MaxCodeBytes));
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
            {
                throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)}, whose native code cannot be read");
            }
            _nativeCode[method] = code;
        }
        try
        {
            return NativeRoutine.Run(code, values, Tick);
        }
        catch (NativeRoutine.Declined d)
        {
            throw Bail(FallbackReason.NativeCode, $"calls {Describe(method)}, native code outside the subset: {d.Message}");
        }
    }
}
