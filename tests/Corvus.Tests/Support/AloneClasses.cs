using System.Reflection;

namespace Corvus.Tests;

/// <summary>Lists the classes whose collection runs alone, so test.ps1 starts them in their own process (<c>dotnet exec Corvus.Tests.dll --alone-classes</c>).</summary>
internal static class AloneClasses
{
    public const string Flag = "--alone-classes";

    /// <summary>
    /// The non-abstract classes of <paramref name="assembly"/> in a collection that runs alone, as "Outer+Nested"
    /// names without the namespace, sorted; empty when there is none.
    /// </summary>
    public static IReadOnlyList<string> Names(Assembly assembly)
    {
        var types = assembly.GetTypes();
        var alone = types
            .SelectMany(t => t.GetCustomAttributesData())
            .Where(a => a.AttributeType == typeof(CollectionDefinitionAttribute)
                && a.NamedArguments.Any(n => n.MemberName == nameof(CollectionDefinitionAttribute.DisableParallelization) && n.TypedValue.Value is true))
            .Select(a => (string)a.ConstructorArguments[0].Value!)
            .ToHashSet(StringComparer.Ordinal);
        return [.. types
            .Where(t => !t.IsAbstract && t.GetCustomAttributesData().Any(a =>
                a.AttributeType == typeof(CollectionAttribute) && a.ConstructorArguments is [{ Value: string name }] && alone.Contains(name)))
            .Select(t => t.FullName![(t.Namespace!.Length + 1)..])
            .Order(StringComparer.Ordinal)];
    }

    /// <summary>Prints one <c>class Name</c> line per <see cref="Names"/> entry of this assembly; exit code 0.</summary>
    public static int Main()
    {
        foreach (var name in Names(typeof(AloneClasses).Assembly)) Console.WriteLine("class " + name);
        return 0;
    }
}
