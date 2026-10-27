using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Corvus.Native.Providers;

/// <summary>Worker folders no other account can open: a protected DACL (user, SYSTEM, Administrators) on Windows, mode 0700 elsewhere.</summary>
/// <remarks>So no other account can replace what a worker runs or read what it writes, even under a shared
/// CORVUS_DATA_DIR or TEMP.</remarks>
public static class PrivateFolder
{
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
