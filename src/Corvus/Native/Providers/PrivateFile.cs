using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Corvus.Native.Providers;

/// <summary>Whether an open file can be written only by this account, SYSTEM and Administrators (Windows) or its owner (POSIX).</summary>
public static class PrivateFile
{
    /// <summary>Null when no other account can write <paramref name="file"/>; else who can, or why that is unknown.</summary>
    public static string? OtherWriters(FileStream file)
    {
        try
        {
            if (OperatingSystem.IsWindows()) return WindowsWriters(file);
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) return PosixWriters(file);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException
                                       or DllNotFoundException or EntryPointNotFoundException)
        {
            return $"has an owner and access list that could not be read ({ex.Message})";
        }
        return "has an owner and access list this platform does not report";
    }

    /// <summary>
    /// Opens <paramref name="path"/> for writing at its end; a new file is
    /// created writable only by this account, SYSTEM and Administrators
    /// (Windows) or with mode 0600 (POSIX). An existing file keeps its access.
    /// </summary>
    public static FileStream OpenAppend(string path)
    {
        if (!OperatingSystem.IsWindows())
            return new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Append, Access = FileAccess.Write, Share = FileShare.ReadWrite | FileShare.Delete,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        // FileMode.Append takes no access-control rights, so the end is sought.
        var stream = new FileInfo(path).Create(FileMode.OpenOrCreate, FileSystemRights.Write | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
            FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.None, acl);
        stream.Seek(0, SeekOrigin.End);
        return stream;
    }

    [SupportedOSPlatform("windows")]
    private static string? WindowsWriters(FileStream file)
    {
        const FileSystemRights write = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership
            | (FileSystemRights)0x10000000 /* GENERIC_ALL */ | (FileSystemRights)0x40000000 /* GENERIC_WRITE */;
        var acl = file.GetAccessControl();
        var trusted = new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) };
        var others = new List<string>();
        // The owner can rewrite the access list whatever it grants.
        if (acl.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && !trusted.Contains(owner)) others.Add(Name(owner));
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && (rule.FileSystemRights & write) != 0
                && rule.IdentityReference is SecurityIdentifier sid && !trusted.Contains(sid))
                others.Add(Name(sid));
        return others.Count == 0 ? null : $"is writable by {string.Join(", ", others.Distinct(StringComparer.OrdinalIgnoreCase))}";
    }

    [SupportedOSPlatform("windows")]
    private static string Name(SecurityIdentifier sid)
    {
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch (SystemException) { return sid.Value; }
    }

    [UnsupportedOSPlatform("windows")]
    private static string? PosixWriters(FileStream file)
    {
        var mode = File.GetUnixFileMode(file.SafeFileHandle);
        if (Owner(file) is not { } uid) return "has an owner this platform does not report";
        var self = geteuid();
        if (uid != self) return $"is owned by uid {uid}, not {self}";
        return (mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0 ? "is writable by its group or others" : null;
    }

    private static uint? Owner(FileStream file)
    {
        bool added = false;
        try
        {
            file.SafeFileHandle.DangerousAddRef(ref added);
            return SystemNativeFStat(file.SafeFileHandle.DangerousGetHandle(), out var status) == 0 ? status.Uid : null;
        }
        finally
        {
            if (added) file.SafeFileHandle.DangerousRelease();
        }
    }

    /// <summary>The leading fields of the runtime's own platform-neutral stat record; the padding covers the rest.</summary>
    [StructLayout(LayoutKind.Sequential, Size = 256)]
    private struct FileStatus
    {
        public int Flags;
        public int Mode;
        public uint Uid;
        public uint Gid;
    }

    // fstat(2) through the .NET runtime's shim, whose FileStatus layout is the same on every Unix.
    [DllImport("libSystem.Native", EntryPoint = "SystemNative_FStat")]
    private static extern int SystemNativeFStat(IntPtr fd, out FileStatus status);

    [DllImport("libc")]
    private static extern uint geteuid();
}
