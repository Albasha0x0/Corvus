namespace Corvus.Tests;

/// <summary>Tests that set process-wide state the server reads (CORVUS_RESULT_MODE, StuckExit): run with nothing in parallel.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessEnvironmentCollection
{
    public const string Name = "ProcessEnvironment";
}
