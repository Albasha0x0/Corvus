using System.Globalization;

namespace Corvus.Native.Providers.Live;

/// <summary>The Frida releases sessions are tested on, and the oldest the session script runs on.</summary>
public static class FridaVersions
{
    /// <summary>Process.attachModuleObserver and the 17.x Module API; older releases are refused.</summary>
    public static readonly Version Required = new(17, 0, 0);
    /// <summary>The oldest release the live tests passed on.</summary>
    public static readonly Version TestedFrom = new(17, 24, 3);
    /// <summary>The first release outside the range: on 17.25.0 a program that starts a child process ends with an
    /// access violation and a managed program's assembly load is not reported (Windows x64).</summary>
    public static readonly Version TestedBefore = new(17, 25, 0);

    public static string TestedRange => $"{TestedFrom} to {TestedBefore.Major}.{TestedBefore.Minor - 1}.x";

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

    public static bool Tested(Version v) => v >= TestedFrom && v < TestedBefore;

    /// <summary>Why sessions cannot run on this Frida (provider_unavailable), or null.</summary>
    public static string? Refusal(string? version) => Parse(version) is { } v && v < Required
        ? $"Frida {version} is older than {Required}, the oldest release the session script runs on (tested: {TestedRange})."
        : null;

    /// <summary>The note for a Frida outside the tested range (sessions still open), or null.</summary>
    public static string? Warning(string? version) => Parse(version) is { } v && Tested(v) ? null
        : $"Frida {version ?? "(unknown version)"} is outside the tested range {TestedRange}; stops, module events or coverage may differ.";

    /// <summary>The release the private environment installs (--live-install-frida).</summary>
    public const string Pinned = "17.24.3";

    /// <summary>SHA-256 of the PyPI wheels of <see cref="Pinned"/> per platform (os-arch); pip may pick any listed wheel.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> WheelHashes = new Dictionary<string, string[]>
    {
        ["windows-x64"] = ["61f5a53b146e0e7755d6c2bfa5405e14fe2373818ae5d98105c4eeca3face7d1"],
        ["windows-arm64"] = ["049e4056c79e6bffb8365358e416bfc62fd2490d70de99dadf7e673905149ff4"],
        ["linux-x64"] = ["2ba706b7385d56111af5c6cced55361168d3d93babdb300d2ea2b7f76d58a289", "d0cf64f883a44c9353e5ede765c2ba28030053a8a077a7d4f20a2bf99a810ad2"],
        ["linux-arm64"] = ["c49b6644b5b18f630957b6e0296d4bd4b79705cda89965068d84b63c174c188f", "73aeac96e5cfb4a739129e7ea631acb9926c4084d2790836a0b61b7ac4267f33"],
        ["macos-x64"] = ["837f0c74ebac09c6cb99f5631f58ac852afbd3a25bfc1d66971cc3e3b7aad953"],
        ["macos-arm64"] = ["767ebb154a896683b75e011e1134a08e8ec31ff6e8968dea8d15a18b37a25cac"],
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
