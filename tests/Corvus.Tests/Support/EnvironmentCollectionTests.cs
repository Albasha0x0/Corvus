using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// A CORVUS_* variable set process-wide is read by every test running at that moment: a class that sets one runs in a
/// collection that keeps it from the tests that read it.
/// </summary>
public sealed partial class EnvironmentCollectionTests
{
    /// <summary>
    /// Collections that keep a class's settings from the tests that read them: ProcessEnvironment and SerialTimingTests run
    /// alone, and the external tool collection holds every class that sets or reads the external tools' variables.
    /// </summary>
    private static readonly string[] Isolating = [ProcessEnvironmentCollection.Name, nameof(SerialTimingTests), ExternalToolEnvironmentCollection.Name];

    [Trait("Smoke", "push")]
    [Fact]
    public void A_class_that_sets_a_CORVUS_variable_runs_in_an_isolating_collection()
    {
        var setters = new[]
        {
            typeof(Environment).GetMethod(nameof(Environment.SetEnvironmentVariable), [typeof(string), typeof(string)])!,
            typeof(EnvironmentScope).GetMethod(nameof(EnvironmentScope.Set))!,
            typeof(EnvironmentScope).GetMethod(nameof(EnvironmentScope.SetProcessWide))!,
        };
        var rerun = typeof(ChildTest).GetMethod(nameof(ChildTest.Rerun))!;
        var offenders = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var type in typeof(EnvironmentCollectionTests).Assembly.GetTypes())
        {
            // Lambdas and async bodies belong to the class that wrote them; a nested test class is a class of its own.
            var owner = type;
            while (owner.DeclaringType != null && owner.IsDefined(typeof(CompilerGeneratedAttribute))) owner = owner.DeclaringType;
            // Settings made before any test runs (the module initializer, the test framework) race with nothing.
            if (typeof(ITestFramework).IsAssignableFrom(owner)) continue;
            var collection = owner.GetCustomAttributesData().FirstOrDefault(a => a.AttributeType == typeof(CollectionAttribute))?.ConstructorArguments[0].Value as string;
            if (collection != null && Isolating.Contains(collection)) continue;
            const BindingFlags all = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
            foreach (var method in type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all)))
            {
                if (method.IsDefined(typeof(ModuleInitializerAttribute))) continue;
                var (names, calls) = Scan(method);
                // A body that ChildTest.Rerun runs in a process of its own sets the variable for that process only.
                if (names.Count > 0 && calls.Any(c => setters.Contains(c)) && !calls.Contains(rerun))
                    offenders.Add($"{owner.FullName}: {string.Join(", ", names.Order())}");
            }
        }
        Assert.True(offenders.Count == 0, "Classes that set CORVUS_* variables outside [Collection(ProcessEnvironmentCollection.Name)] "
            + "(or the external tool collection for its own variables):\n" + string.Join("\n", offenders));
    }

    // Regression: CORVUS_WORKER_HOST=0 set by NativeCapaTests and CapabilityChangesTests turned off the shared file
    // worker of a test running beside them (CI run 40097321516, 814968d7).
    [Fact]
    public void A_class_in_the_external_tool_collection_sets_only_the_tools_own_variables()
    {
        // Read through ExternalTools.ReadVariable or named CORVUS_TEST_*; any other variable reaches every concurrent test.
        var tools = Corvus.Native.Providers.ExternalTools.Table.Select(t => t.Variable)
            .Append("CORVUS_DIE").Append(Corvus.Core.ReferencePacks.OfflineVariable).Append(Corvus.Native.Pdb.PdbLocator.CacheVariable)
            .ToHashSet(StringComparer.Ordinal);
        var setters = new[]
        {
            typeof(Environment).GetMethod(nameof(Environment.SetEnvironmentVariable), [typeof(string), typeof(string)])!,
            typeof(EnvironmentScope).GetMethod(nameof(EnvironmentScope.Set))!,
            typeof(EnvironmentScope).GetMethod(nameof(EnvironmentScope.SetProcessWide))!,
        };
        var offenders = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var type in typeof(EnvironmentCollectionTests).Assembly.GetTypes())
        {
            var owner = type;
            while (owner.DeclaringType != null && owner.IsDefined(typeof(CompilerGeneratedAttribute))) owner = owner.DeclaringType;
            var collection = owner.GetCustomAttributesData().FirstOrDefault(a => a.AttributeType == typeof(CollectionAttribute))?.ConstructorArguments[0].Value as string;
            if (collection != ExternalToolEnvironmentCollection.Name) continue;
            const BindingFlags all = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
            foreach (var method in type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all)))
            {
                var (names, calls) = Scan(method);
                if (calls.Any(c => setters.Contains(c))
                    && names.Where(n => Variable().IsMatch(n) && !tools.Contains(n) && !n.StartsWith("CORVUS_TEST_", StringComparison.Ordinal)).ToList() is { Count: > 0 } other)
                    offenders.Add($"{owner.FullName}: {string.Join(", ", other.Order())}");
            }
        }
        Assert.True(offenders.Count == 0, "Classes in the external tool collection that set variables other than the tools' own "
            + "(WorkerPool.UseShared turns the worker host off in one flow):\n" + string.Join("\n", offenders));
    }

    [GeneratedRegex("^CORVUS_[A-Z0-9_]+$")]
    private static partial Regex Variable();

    private static readonly Dictionary<short, OpCode> OpCodesByValue = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(f => (OpCode)f.GetValue(null)!).ToDictionary(o => o.Value);

    /// <summary>The CORVUS_* strings a method's body loads and the methods it calls; both empty for a method without a body.</summary>
    private static (HashSet<string> Names, List<MethodBase> Calls) Scan(MethodBase method)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var calls = new List<MethodBase>();
        var il = method.GetMethodBody()?.GetILAsByteArray();
        if (il == null) return (names, calls);
        for (int i = 0; i < il.Length;)
        {
            short value = il[i] == 0xFE ? (short)(0xFE00 | il[i + 1]) : il[i];
            i += il[i] == 0xFE ? 2 : 1;
            var op = OpCodesByValue[value];
            if (op.OperandType == OperandType.InlineString && method.Module.ResolveString(BitConverter.ToInt32(il, i)) is { } s && s.StartsWith("CORVUS_", StringComparison.Ordinal))
                names.Add(s);
            else if (op.OperandType == OperandType.InlineMethod)
            {
                try { calls.Add(method.Module.ResolveMethod(BitConverter.ToInt32(il, i), method.DeclaringType?.GetGenericArguments(), method.IsGenericMethod ? method.GetGenericArguments() : null)!); }
                catch (ArgumentException) { }
            }
            i += op.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(il, i),
                _ => 4,
            };
        }
        return (names, calls);
    }
}
