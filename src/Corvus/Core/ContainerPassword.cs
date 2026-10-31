namespace Corvus.Core;

/// <summary>
/// The password the caller gave for the current call; null when none was
/// given. Readers try only this one and never a built-in or default.
/// </summary>
public static class ContainerPassword
{
    private static readonly AsyncLocal<string?> InForce = new();

    /// <summary>The current call's password; null outside a call or when none was given.</summary>
    public static string? Current => InForce.Value;

    /// <summary>Makes <paramref name="password"/> the current call's password until the scope is disposed; an empty one is none.</summary>
    public static IDisposable Enter(string? password)
    {
        var previous = InForce.Value;
        InForce.Value = string.IsNullOrEmpty(password) ? null : password;
        return new Scope(previous);
    }

    /// <summary>The note for an entry the password did not open; the password is never in it.</summary>
    public static string NotRead(string entry, bool given) =>
        $"{entry}: not read ({(given ? "the password did not decrypt it" : "encrypted; pass password to read it")}).";

    private sealed class Scope(string? previous) : IDisposable
    {
        public void Dispose() => InForce.Value = previous;
    }
}

/// <summary>An entry an encrypted archive holds that the password did not open.</summary>
public sealed class EntryLockedException(bool given) : IOException("the entry is encrypted")
{
    /// <summary>Whether the caller gave a password that failed.</summary>
    public bool Given { get; } = given;
}
