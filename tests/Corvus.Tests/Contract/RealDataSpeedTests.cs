using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;

namespace Corvus.Tests;

/// <summary>
/// A test that reads real-world data runs for as long as its data takes, so it stays out of the quick set: it carries
/// Speed=Slow on the method or its class. Real data is a test attribute named for it (RequiresRealDataFact,
/// LiveRealDataFact, RequiresPathFact), or a variable of <see cref="RealData"/> or <see cref="DataVariables"/> named in
/// the test's code or in the methods of this assembly it calls.
/// </summary>
public class RealDataSpeedTests
{
    /// <summary>Variables naming data outside the repository that tests read directly instead of through <see cref="RealData"/>.</summary>
    private static readonly string[] DataVariables =
    [
        "CORVUS_ACCURACY_DIR", "CORVUS_ARK_DIR", "CORVUS_AUTOIT_RELEASES", "CORVUS_AUTOIT_SCRIPTS", "CORVUS_CAPTURES", "CORVUS_DIFF_PAIRS", "CORVUS_EXPORT_LIST", "CORVUS_FIRMWARE_IMAGES",
        "CORVUS_GAMEMAKER_DATA", "CORVUS_GO_SAMPLES", "CORVUS_GODOT_PACKS", "CORVUS_HBC_DIR", "CORVUS_IDA_ORACLE_FILES", "CORVUS_IL2CPP_BUILD", "CORVUS_IL2CPP_BUILD_DUMP",
        "CORVUS_IL2CPP_GENERICS_BUILD", "CORVUS_IL2CPP_MOBILE", "CORVUS_INSTALLERS", "CORVUS_JAVA_JARS", "CORVUS_LUA_CHUNKS",
        "CORVUS_NATIVE_ADAPTER_SAMPLE", "CORVUS_NATIVE_LARGE_IMAGE", "CORVUS_NATIVE_STDIO_SAMPLE", "CORVUS_PACKAGES_BAD",
        "CORVUS_PACKAGES_GOOD", "CORVUS_PDB_SAMPLE", "CORVUS_PIPELINE_SAMPLE", "CORVUS_PIPELINE_SAMPLES", "CORVUS_R2R_COMPOSITE_DIR", "CORVUS_LINUX_APPS", "CORVUS_RPM_PACKAGES",
        "CORVUS_STUB_APPS", "CORVUS_UNITY_BUILDS", "CORVUS_VCALL_SAMPLE", "CORVUS_WASM_DIR", "CORVUS_WPF_APPS",
    ];

    /// <summary>Real-data tests that finish in seconds and stay in the quick set ("Class.Method": reason).</summary>
    private static readonly Dictionary<string, string> Quick = new(StringComparer.Ordinal);

    [Fact]
    public void Every_real_data_test_is_slow()
    {
        var tests = Tests().ToList();
        var offenders = tests.Where(t => !IsSlow(t.Type, t.Method) && ReadsRealData(t.Method)).Select(t => t.Name)
            .Where(n => !Quick.ContainsKey(n)).Distinct().Order(StringComparer.Ordinal).ToList();
        Assert.True(offenders.Count == 0, "real-data tests without [Trait(\"Speed\", \"Slow\")] on the method or class:\n" + string.Join("\n", offenders));
        var names = tests.Select(t => t.Name).ToHashSet(StringComparer.Ordinal);
        var stale = Quick.Keys.Where(k => !names.Contains(k)).ToList();
        Assert.True(stale.Count == 0, "Quick names tests that no longer exist: " + string.Join(", ", stale));
    }

    [Fact]
    public void Every_listed_data_variable_is_read_by_a_test()
    {
        var read = Tests().SelectMany(t => Strings(t.Method)).ToHashSet(StringComparer.Ordinal);
        var unread = DataVariables.Where(v => !read.Contains(v)).ToList();
        Assert.True(unread.Count == 0, "DataVariables names variables no test reads: " + string.Join(", ", unread));
    }

    private static readonly HashSet<string> Variables = [.. typeof(RealData).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.IsLiteral).Select(f => (string)f.GetRawConstantValue()!), .. DataVariables];

    private static bool ReadsRealData(MethodInfo test) =>
        test.CustomAttributes.Any(a => typeof(FactAttribute).IsAssignableFrom(a.AttributeType)
            && (a.AttributeType.Name.Contains("RealData", StringComparison.Ordinal) || a.AttributeType == typeof(RequiresPathFactAttribute)))
        || Strings(test).Overlaps(Variables);

    private static IEnumerable<(Type Type, MethodInfo Method, string Name)> Tests() =>
        from type in typeof(RealDataSpeedTests).Assembly.GetTypes()
        where type.IsClass && !type.IsAbstract
        from method in type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
        where method.IsDefined(typeof(FactAttribute), inherit: true)
        select (type, method, $"{type.Name}.{method.Name}");

    private static bool IsSlow(Type type, MethodInfo test)
    {
        static bool Marked(MemberInfo member) => member.CustomAttributes.Any(a => a.AttributeType == typeof(TraitAttribute)
            && a.ConstructorArguments is [{ Value: "Speed" }, { Value: "Slow" }]);
        if (Marked(test)) return true;
        for (Type? t = type; t != null; t = t.BaseType)
            for (Type? outer = t; outer != null; outer = outer.DeclaringType)
                if (Marked(outer)) return true;
        return false;
    }

    private static readonly Dictionary<short, OpCode> Codes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(c => c.Value);

    /// <summary>String literals loaded by <paramref name="root"/> and by the methods of this assembly it calls or makes delegates of.</summary>
    private static HashSet<string> Strings(MethodBase root)
    {
        var strings = new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<MethodBase>();
        var queue = new Queue<MethodBase>([root]);
        while (queue.TryDequeue(out var method))
        {
            if (!seen.Add(method)) continue;
            if (method.GetCustomAttribute<StateMachineAttribute>() is { } machine
                && machine.StateMachineType.GetMethod("MoveNext", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public) is { } moveNext)
                queue.Enqueue(moveNext);
            var il = method.GetMethodBody()?.GetILAsByteArray();
            if (il == null) continue;
            for (int i = 0; i < il.Length;)
            {
                short value = il[i] == 0xFE ? (short)(0xFE00 | il[i + 1]) : il[i];
                i += il[i] == 0xFE ? 2 : 1;
                if (!Codes.TryGetValue(value, out var code)) break;
                if (code.OperandType == OperandType.InlineString)
                    strings.Add(method.Module.ResolveString(BitConverter.ToInt32(il, i)));
                else if (code.OperandType == OperandType.InlineMethod)
                {
                    try
                    {
                        var callee = method.Module.ResolveMethod(BitConverter.ToInt32(il, i),
                            method.DeclaringType is { IsGenericType: true } d ? d.GetGenericArguments() : null, method.IsGenericMethod ? method.GetGenericArguments() : null);
                        if (callee?.Module == root.Module) queue.Enqueue(callee);
                    }
                    // A generic member whose context this walk does not track.
                    catch (ArgumentException) { }
                }
                i += code.OperandType switch
                {
                    OperandType.InlineNone => 0,
                    OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                    OperandType.InlineVar => 2,
                    OperandType.InlineI8 or OperandType.InlineR => 8,
                    OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(il, i),
                    _ => 4,
                };
            }
        }
        return strings;
    }
}
