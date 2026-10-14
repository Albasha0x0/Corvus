namespace Corvus.Tests;

/// <summary>Tests that set process-wide environment variables the server reads (CORVUS_RESULT_MODE): run with nothing in parallel.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ProcessEnvironmentCollection
{
    public const string Name = "ProcessEnvironment";
}
