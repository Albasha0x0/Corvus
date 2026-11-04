using System.Globalization;

namespace Corvus.Native.Providers.Live;

/// <summary>The Frida releases sessions are tested on, and the oldest the session script runs on.</summary>
public static class FridaVersions
{
    /// <summary>Process.attachModuleObserver and the 17.x Module API; older releases are refused.</summary>
    public static readonly Version Required = new(17, 0, 0);
    /// <summary>The oldest release the live tests passed on.</summary>
    public static readonly Version TestedFrom = new(17, 24, 3);
    /// <summary>The first release outside the range.</summary>
    public static readonly Version TestedBefore = new(17, 26, 0);
    /// <summary>The release inside the range that is not tested: an attached program that loads the compatibility
    /// shim engine ends with an access violation at exit (frida/frida-gum#1200, Windows x64, fixed in 17.25.1).</summary>
    public static readonly Version Excluded = new(17, 25, 0);

    /// <summary>The tested releases as text, naming the excluded release as a gap.</summary>
    public static string TestedRange =>
        $"{TestedFrom} to {Excluded.Major}.{Excluded.Minor - 1}.x and {Excluded.Major}.{Excluded.Minor}.{Excluded.Build + 1} to {TestedBefore.Major}.{TestedBefore.Minor - 1}.x";

    /// <summary>The pip version specifier of the tested releases.</summary>
    public static string TestedSpecifier => $">={TestedFrom},!={Excluded},<{TestedBefore}";

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

    /// <summary>True when the version lies in the tested range and is not the excluded one.</summary>
    public static bool Tested(Version v) => v >= TestedFrom && v < TestedBefore && v != Excluded;

    /// <summary>Why sessions cannot run on this Frida (provider_unavailable), or null.</summary>
    public static string? Refusal(string? version) => Parse(version) is { } v && v < Required
        ? $"Frida {version} is older than {Required}, the oldest release the session script runs on (tested: {TestedRange})."
        : null;

    /// <summary>The note for a Frida outside the tested range (sessions still open), or null.</summary>
    public static string? Warning(string? version) => Parse(version) is { } v && Tested(v) ? null
        : $"Frida {version ?? "(unknown version)"} is outside the tested range {TestedRange}; stops, module events or coverage may differ.";

    /// <summary>The release the private environment installs (--live-install-frida).</summary>
    public const string Pinned = "17.25.2";

    /// <summary>SHA-256 of the PyPI wheels of <see cref="Pinned"/> per platform (os-arch); pip may pick any listed wheel.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> WheelHashes = new Dictionary<string, string[]>
    {
        ["windows-x64"] = ["0b4417264041e227364df268c77b8d4d8a9920beffd5ac55cec2a06d74e0839e"],
        ["windows-arm64"] = ["ab246bc60f44868dfdc84d5702a33a640a93f59d40f90c2c98bd12db39016c89"],
        ["linux-x64"] = ["226998c9b3cb79d99871138533d2c58525ede3b1ea45647c6483d28ced8abb73", "55cb5f7f6f75922a37e451449ec71e695400e3d6a009c275c285abf88a49dd53"],
        ["linux-arm64"] = ["bef0bc2be97d5c560d7d499cafe8ddfdd3907264d4fdc4d9f4402b920c5517e2", "ba69324c16b3ea018241519621d69f75896adbdce07f1afb1f60d7a322d17175"],
        ["macos-x64"] = ["0b8722c52b5725360af7db805e5fe82c0e6dd96e9098712e2e8dd934810452d8"],
        ["macos-arm64"] = ["090b0107b225c18a18e2edf7f0a53da17338e95d7c9909983cc4a1d56af0101e"],
    };

    /// <summary>frida's one dependency, below Python 3.11 only.</summary>
    private const string TypingExtensions =
        "typing_extensions==4.12.2; python_version < \"3.11\" --hash=sha256:04e5ca0351e0f3f85c6853954072df659d0d13fac324d0072316b67d7794700d";

    /// <summary>The os-arch key of this machine, as <see cref="WheelHashes"/> names it.</summary>
    public static string Platform(bool windows, bool linux, System.Runtime.InteropServices.Architecture arch) =>
        (windows ? "windows" : linux ? "linux" : "macos") + "-" + arch.ToString().ToLowerInvariant();

    /// <summary>The pip requirements (with --require-hashes) for <paramref name="platform"/>, or null when no wheel is pinned for it.</summary>
    public static string? Requirements(string platform) => WheelHashes.TryGetValue(platform, out var hashes)
        ? $"frida=={Pinned} " + string.Join(" ", hashes.Select(h => "--hash=sha256:" + h)) + "\n" + TypingExtensions + "\n"
        : null;
}
