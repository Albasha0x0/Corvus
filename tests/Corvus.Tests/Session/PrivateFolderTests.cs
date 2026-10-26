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
