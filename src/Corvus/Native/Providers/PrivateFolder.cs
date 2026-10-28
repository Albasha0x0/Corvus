using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Corvus.Native.Providers;

/// <summary>Worker folders no other account can open: a protected DACL (user, SYSTEM, Administrators) on Windows, mode 0700 elsewhere.</summary>
/// <remarks>So no other account can replace what a worker runs or read what it writes, even under a shared
/// CORVUS_DATA_DIR or TEMP.</remarks>
public static class PrivateFolder
{
    private static readonly ConcurrentDictionary<string, bool> Checked = new(OperatingSystem.IsLinux() ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);

    /// <summary>Creates <paramref name="path"/> and parents; an existing Windows folder gets the DACL only when it differs, as a change propagates inside.</summary>
    public static string Create(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var dir = new DirectoryInfo(path);
            if (dir.Parent is { } parent) Directory.CreateDirectory(parent.FullName);
            if (dir.Exists) { if (!IsPrivate(dir.GetAccessControl())) dir.SetAccessControl(OwnerOnly()); }
            else
            {
                try { dir.Create(OwnerOnly()); }
                // Created by another process in the meantime: the same DACL is set on it.
                catch (IOException) when (Directory.Exists(path)) { dir.SetAccessControl(OwnerOnly()); }
            }
        }
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    /// <summary>
    /// The full path of a folder only this account can write: created private
    /// when missing, else checked once per process. Throws
    /// UnauthorizedAccessException for a link, a folder another account owns, or
    /// one that grants another account write access by its own entries (Windows)
    /// or group or other write bits (POSIX); access a folder only inherits, and
    /// read access, are removed.
    /// </summary>
    public static string Ensure(string path)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (Checked.ContainsKey(full)) return full;
        if (!Path.Exists(full)) Create(full);
        if (Refusal(full, tighten: true) is { } why)
            throw new UnauthorizedAccessException($"{full} {why}; Corvus keeps its data only in folders no other account can write.");
        Checked[full] = true;
        return full;
    }

    /// <summary>
    /// A path under this account's own temporary folder
    /// (TEMP/corvus-&lt;account key&gt;), which <see cref="Ensure"/> keeps
    /// private.
    /// </summary>
    public static string Temp(params string[] parts) => Path.Combine([Ensure(Path.Combine(Path.GetTempPath(), TempRootName)), .. parts]);

    /// <summary>
    /// This account's temporary folder name: corvus-&lt;uid&gt; on POSIX,
    /// corvus-&lt;16 hex of the user SID's SHA-256&gt; on Windows.
    /// </summary>
    public static string TempRootName { get; } = "corvus-" + (OperatingSystem.IsWindows()
        ? Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(WindowsIdentity.GetCurrent().User!.Value)))[..16]
        : PrivateFile.EffectiveUser().ToString(System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>
    /// Null when no other account can write the folder at
    /// <paramref name="path"/>; else who can, or why that is unknown. Changes
    /// nothing.
    /// </summary>
    public static string? OtherWriters(string path)
    {
        try { return Refusal(Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)), tighten: false); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                       or DllNotFoundException or EntryPointNotFoundException)
        {
            return $"has an owner and access list that could not be read ({ex.Message})";
        }
    }

    /// <summary>
    /// Why <paramref name="full"/> cannot hold private data, or null when it is
    /// private; <paramref name="tighten"/> removes access the folder only
    /// inherits.
    /// </summary>
    private static string? Refusal(string full, bool tighten)
    {
        if (!Directory.Exists(full)) return "is not a folder";
        if (new DirectoryInfo(full).LinkTarget != null) return "is a link";
        return OperatingSystem.IsWindows() ? WindowsRefusal(full, tighten) : PosixRefusal(full, tighten);
    }

    [SupportedOSPlatform("windows")]
    private static string? WindowsRefusal(string full, bool tighten)
    {
        var dir = new DirectoryInfo(full);
        var acl = dir.GetAccessControl();
        var trusted = Trusted();
        if (acl.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !trusted.Contains(owner))
            return $"is owned by {PrivateFile.Name(owner)}";
        var others = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & PrivateFile.WriteRights) != 0
                        && r.IdentityReference is SecurityIdentifier sid && !trusted.Contains(sid))
            .ToList();
        if (others.FirstOrDefault(r => !r.IsInherited) is { } granted)
            return $"grants write access to {PrivateFile.Name((SecurityIdentifier)granted.IdentityReference)}";
        // Access only inherited from the parent was never granted to this
        // folder: it is replaced.
        if (others.Count > 0 && !tighten) return $"is writable by {PrivateFile.Name((SecurityIdentifier)others[0].IdentityReference)}";
        if (others.Count > 0) dir.SetAccessControl(OwnerOnly());
        return null;
    }

    /// <summary>
    /// The accounts a private folder may grant: the user, SYSTEM,
    /// Administrators and CREATOR OWNER (the creator of each entry).
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier[] Trusted() =>
    [
        WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), new SecurityIdentifier(WellKnownSidType.CreatorOwnerSid, null),
    ];

    [UnsupportedOSPlatform("windows")]
    private static string? PosixRefusal(string full, bool tighten)
    {
        if (PrivateFile.OwnerOf(full) is not { } uid) return "has an owner this platform does not report";
        var self = PrivateFile.EffectiveUser();
        if (uid != self) return $"is owned by uid {uid}, not {self}";
        var mode = File.GetUnixFileMode(full);
        if ((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0) return "is writable by its group or others";
        const UnixFileMode owner = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (tighten && mode != owner) File.SetUnixFileMode(full, owner);
        return null;
    }

    /// <summary>A protected, inherited DACL granting full control to the user, SYSTEM (services load helpers from it) and Administrators.</summary>
    [SupportedOSPlatform("windows")]
    internal static DirectorySecurity OwnerOnly()
    {
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }

    /// <summary>Whether <paramref name="acl"/> is protected and grants exactly what <see cref="OwnerOnly"/> grants.</summary>
    [SupportedOSPlatform("windows")]
    internal static bool IsPrivate(DirectorySecurity acl)
    {
        static IEnumerable<string> Rules(DirectorySecurity a) => a.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(r => $"{r.IdentityReference.Value} {r.AccessControlType} {(int)r.FileSystemRights} {r.InheritanceFlags} {r.PropagationFlags} {r.IsInherited}")
            .Order(StringComparer.Ordinal);
        return acl.AreAccessRulesProtected && Rules(acl).SequenceEqual(Rules(OwnerOnly()));
    }
}
