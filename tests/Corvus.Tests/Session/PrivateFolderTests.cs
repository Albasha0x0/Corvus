using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>Worker folders: no other user account may open them, and what is created inside inherits that.</summary>
public sealed class PrivateFolderTests
{
    [SupportedOSPlatform("windows")]
    private static List<string> Grants(FileSystemSecurity acl) =>
        [.. acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(r => $"{r.IdentityReference.Value} {r.AccessControlType} {r.FileSystemRights}").Order(StringComparer.Ordinal)];

    [SupportedOSPlatform("windows")]
    private static List<string> Expected() =>
        [.. new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) }
            .Select(s => $"{s.Value} Allow FullControl").Order(StringComparer.Ordinal)];

    [WindowsFact, SupportedOSPlatform("windows")]
    public void A_new_folder_grants_only_the_user_system_and_administrators_and_its_files_inherit_that()
    {
        using var dir = new TempDir();
        var path = PrivateFolder.Create(dir.File("a/b/worker"));
        var acl = new DirectoryInfo(path).GetAccessControl();
        Assert.True(acl.AreAccessRulesProtected);
        Assert.Equal(Expected(), Grants(acl));
        File.WriteAllText(Path.Combine(path, "script.py"), "");
        Assert.Equal(Expected(), Grants(new FileInfo(Path.Combine(path, "script.py")).GetAccessControl()));
        Assert.True(PrivateFolder.IsPrivate(acl));
    }

    [WindowsFact, SupportedOSPlatform("windows")]
    public void An_existing_folder_and_its_contents_are_made_private_once()
    {
        using var dir = new TempDir();
        var path = dir.File("existing");
        Directory.CreateDirectory(path);
        File.WriteAllText(Path.Combine(path, "data.bin"), "");
        Assert.False(PrivateFolder.IsPrivate(new DirectoryInfo(path).GetAccessControl()));
        PrivateFolder.Create(path);
        Assert.Equal(Expected(), Grants(new DirectoryInfo(path).GetAccessControl()));
        Assert.Equal(Expected(), Grants(new FileInfo(Path.Combine(path, "data.bin")).GetAccessControl()));
        // A second call finds it private and leaves it as it is.
        var before = new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        PrivateFolder.Create(path);
        Assert.Equal(before, new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
    }

    [PosixFact, UnsupportedOSPlatform("windows")]
    public void A_new_folder_elsewhere_is_mode_0700()
    {
        using var dir = new TempDir();
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(PrivateFolder.Create(dir.File("worker"))));
    }

    [SupportedOSPlatform("windows")]
    private static void Grant(string path, InheritanceFlags inheritance)
    {
        var info = new DirectoryInfo(path);
        var acl = info.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Modify,
            inheritance, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(acl);
    }

    [WindowsFact, SupportedOSPlatform("windows")]
    public void A_data_folder_that_grants_another_account_write_access_is_refused()
    {
        using var dir = new TempDir();
        var path = Directory.CreateDirectory(dir.File("shared")).FullName;
        Grant(path, InheritanceFlags.None);
        var refused = Assert.Throws<UnauthorizedAccessException>(() => PrivateFolder.Ensure(path));
        Assert.Contains("grants write access to", refused.Message, StringComparison.Ordinal);
        Assert.NotNull(PrivateFolder.OtherWriters(path));
    }

    [WindowsFact, SupportedOSPlatform("windows")]
    public void Write_access_a_data_folder_only_inherits_is_removed()
    {
        using var dir = new TempDir();
        var parent = Directory.CreateDirectory(dir.File("parent")).FullName;
        Grant(parent, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        var path = Directory.CreateDirectory(Path.Combine(parent, "data")).FullName;
        Assert.NotNull(PrivateFolder.OtherWriters(path));
        PrivateFolder.Ensure(path);
        Assert.True(PrivateFolder.IsPrivate(new DirectoryInfo(path).GetAccessControl()));
        Assert.Null(PrivateFolder.OtherWriters(path));
    }

    [WindowsFact, SupportedOSPlatform("windows")]
    public void The_relay_refuses_a_build_folder_another_account_can_write()
    {
        using var dir = new TempDir();
        var target = Directory.CreateDirectory(dir.File("publish")).FullName;
        Grant(target, InheritanceFlags.None);
        var refused = Assert.Throws<ArgumentException>(() => Corvus.Relay.RelayCli.Parse(["--target", target, "--state", dir.File("state")]));
        Assert.Contains("no other account can write", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_missing_data_folder_is_created_private_and_the_temporary_folder_is_per_account()
    {
        using var dir = new TempDir();
        var path = PrivateFolder.Ensure(dir.File("new/data"));
        Assert.Null(PrivateFolder.OtherWriters(path));
        var temp = PrivateFolder.Temp("work");
        Assert.Equal(Path.Combine(Path.GetTempPath(), PrivateFolder.TempRootName, "work"), temp);
        Assert.Null(PrivateFolder.OtherWriters(Path.GetDirectoryName(temp)!));
    }

    [PosixFact, UnsupportedOSPlatform("windows")]
    public void A_data_folder_its_group_can_write_is_refused()
    {
        using var dir = new TempDir();
        var path = Directory.CreateDirectory(dir.File("shared")).FullName;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute);
        Assert.Contains("writable by its group or others", Assert.Throws<UnauthorizedAccessException>(() => PrivateFolder.Ensure(path)).Message, StringComparison.Ordinal);
    }

    [PosixFact, UnsupportedOSPlatform("windows")]
    public void A_data_folder_readable_by_others_is_set_to_mode_0700()
    {
        using var dir = new TempDir();
        var path = Directory.CreateDirectory(dir.File("data")).FullName;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        PrivateFolder.Ensure(path);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(path));
    }

    [PosixFact, UnsupportedOSPlatform("windows")]
    public void A_data_folder_that_is_a_symbolic_link_is_refused()
    {
        using var dir = new TempDir();
        var target = Directory.CreateDirectory(dir.File("target")).FullName;
        var link = Directory.CreateSymbolicLink(dir.File("link"), target).FullName;
        Assert.Contains("is a link", Assert.Throws<UnauthorizedAccessException>(() => PrivateFolder.Ensure(link)).Message, StringComparison.Ordinal);
    }

    [PosixNonRootFact, UnsupportedOSPlatform("windows")]
    public void A_data_folder_another_account_owns_is_refused()
    {
        // The file system root is owned by uid 0.
        Assert.Contains("is owned by uid 0", Assert.Throws<UnauthorizedAccessException>(() => PrivateFolder.Ensure("/")).Message, StringComparison.Ordinal);
    }

    [WindowsFact, SupportedOSPlatform("windows")]
    public void A_session_worker_folder_also_lets_sandboxed_programs_read()
    {
        using var dir = new TempDir();
        var path = PrivateFolder.Create(dir.File("live-temp"));
        Corvus.Native.Providers.Live.FridaBackend.AllowSandboxedReads(path);
        var grants = Grants(new DirectoryInfo(path).GetAccessControl());
        Assert.Equal(5, grants.Count);
        Assert.Contains("S-1-15-2-1 Allow ReadAndExecute, Synchronize", grants);
        Assert.Contains(new SecurityIdentifier(WellKnownSidType.RestrictedCodeSid, null).Value + " Allow ReadAndExecute, Synchronize", grants);
    }
}

/// <summary>
/// A fact that runs only on Linux and macOS under an account other than root.
/// </summary>
public sealed class PosixNonRootFactAttribute : FactAttribute
{
    public PosixNonRootFactAttribute()
    {
        if (OperatingSystem.IsWindows()) Skip = "Needs POSIX owners.";
        else if (PrivateFile.EffectiveUser() == 0) Skip = "Runs as root, which owns the folder it reads.";
    }
}
