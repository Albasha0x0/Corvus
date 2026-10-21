using System.Globalization;

namespace Corvus.Native.Providers.Live;

/// <summary>The Frida releases sessions are tested on, and the oldest the session script runs on.</summary>
public static class FridaVersions
{
    /// <summary>Process.attachModuleObserver and the 17.x Module API; older releases are refused.</summary>
    public static readonly Version Required = new(17, 0, 0);
    /// <summary>The oldest release the live tests passed on; the range ends before the next major release.</summary>
    public static readonly Version TestedFrom = new(17, 24, 3);
    public const int TestedMajor = 17;

    public static string TestedRange => $"{TestedFrom} to {TestedMajor}.x";

    /// <summary>The leading major.minor.patch of a version string (17.24.3, 17.5.0-dev.3); null when it has none.</summary>
    public static Version? Parse(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return null;
        var parts = version.Trim().Split('.', 3);
        var numbers = new int[3];
        for (int i = 0; i < 3; i++)
        {
            var digits = i < parts.Length ? new string(parts[i].TakeWhile(char.IsAsciiDigit).ToArray()) : "0";
            if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i])) return null;
        }
        return new Version(numbers[0], numbers[1], numbers[2]);
    }

    public static bool Tested(Version v) => v >= TestedFrom && v.Major == TestedMajor;

    /// <summary>Why sessions cannot run on this Frida (provider_unavailable), or null.</summary>
    public static string? Refusal(string? version) => Parse(version) is { } v && v < Required
        ? $"Frida {version} is older than {Required}, the oldest release the session script runs on (tested: {TestedRange})."
        : null;

    /// <summary>The note for a Frida outside the tested range (sessions still open), or null.</summary>
    public static string? Warning(string? version) => Parse(version) is { } v && Tested(v) ? null
        : $"Frida {version ?? "(unknown version)"} is outside the tested range {TestedRange}; stops, module events or coverage may differ.";
}
