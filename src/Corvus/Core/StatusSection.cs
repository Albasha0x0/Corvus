using System.Reflection;

namespace Corvus.Core;

/// <summary>A value of a server_status section, with where it came from (an option, a variable, the client, a default) when that matters.</summary>
public sealed record StatusField(string Name, string Value, string? Source = null);

public sealed record StatusSection(string Name, IReadOnlyList<StatusField> Fields);

/// <summary>One section of server_status, found by type scan; a new section is a new class.</summary>
/// <remarks>Implementations need a parameterless constructor; services come from the call's provider.</remarks>
public interface IStatusSection
{
    /// <summary>Lower-case section name (budget, results, caches, calls, workers, run).</summary>
    string Name { get; }

    /// <summary>Position among the sections, lowest first.</summary>
    int Order => 100;

    IEnumerable<StatusField> Fields(IServiceProvider services);
}

public static class StatusSections
{
    private static readonly Lazy<IReadOnlyList<Type>> Types = new(() =>
        [.. typeof(IStatusSection).Assembly.GetTypes().Where(t => t is { IsClass: true, IsAbstract: false } && typeof(IStatusSection).IsAssignableFrom(t)
            && t.GetConstructor(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance, Type.EmptyTypes) != null)]);

    /// <summary>Every section, in order; a section that throws reports the problem as its one field.</summary>
    public static IReadOnlyList<StatusSection> Collect(IServiceProvider services) =>
        Collect(services, Types.Value.Select(t => (IStatusSection)Activator.CreateInstance(t, nonPublic: true)!));

    /// <summary>The sections by order then name, each read on its own thread so a call waits only for the slowest.</summary>
    internal static IReadOnlyList<StatusSection> Collect(IServiceProvider services, IEnumerable<IStatusSection> sections)
    {
        var reads = sections.OrderBy(s => s.Order).ThenBy(s => s.Name, StringComparer.Ordinal)
            .Select(s => Task.Factory.StartNew(() =>
            {
                try { return new StatusSection(s.Name, [.. s.Fields(services).Select(f => f with { Source = ConfigFile.Shown(f.Source) })]); }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    return new StatusSection(s.Name, [new StatusField("error", ex.Message)]);
                }
            }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToList();
        return [.. reads.Select(r => r.GetAwaiter().GetResult())];
    }
}
