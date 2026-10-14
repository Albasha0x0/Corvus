using System.Runtime.CompilerServices;
using Corvus.Core;

namespace Corvus.Tests;

internal static class LockScopeSetup
{
    /// <summary>Every in-process tool call fails when it reads a loaded module or decompiler reader outside the workspace lock.</summary>
    [ModuleInitializer]
    internal static void CheckLockScope() => AssemblyWorkspace.CheckLockScope = true;
}
