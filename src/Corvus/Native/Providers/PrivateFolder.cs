using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Corvus.Native.Providers;

/// <summary>
/// Folders a worker process runs code from or writes into (scripts, compiled workers, temporary files, memory captures):
/// no other user account may open them, so it cannot replace what a worker runs or read what it writes, even under a
/// shared CORVUS_DATA_DIR or TEMP. On Windows the folder's DACL is protected and grants full control to the current user,
/// SYSTEM and Administrators, as a user profile folder does, inherited by everything inside; elsewhere a new folder is
/// created with mode 0700.
/// </summary>
public static class PrivateFolder
{
    /// <summary>
    /// Creates <paramref name="path"/> and its missing parents; an existing folder on Windows gets the same DACL unless it
    /// already has it, since a change propagates through everything inside.
    /// </summary>
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
    /// A protected DACL: full control for the current user, SYSTEM and Administrators, inherited by files and folders
    /// inside. SYSTEM and Administrators keep the access they have to a profile folder: a session on a service running
    /// as SYSTEM loads its helper files from a worker folder.
    /// </summary>
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
