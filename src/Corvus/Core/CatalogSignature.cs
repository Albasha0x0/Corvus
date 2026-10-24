using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;

namespace Corvus.Core;

/// <summary>
/// Windows catalog signatures (files signed through a system security catalog rather than an embedded signature, as
/// the .NET Framework's own files are): WinVerifyTrust checks the file against its catalog without network access, and
/// the catalog's signer is checked like an embedded signature.
/// </summary>
public static class CatalogSignature
{
    /// <summary>
    /// Null when <paramref name="path"/> is in a system catalog signed by <paramref name="organization"/>; else why not.
    /// <paramref name="note"/> names a check of the catalog's signer that could not be made (revocation).
    /// </summary>
    public static string? Verify(string path, string organization, out string? note)
    {
        note = null;
        if (!OperatingSystem.IsWindows()) return "catalog signatures are checked on Windows only";
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        string? last = null;
        foreach (var algorithm in new[] { "SHA256", null })
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
            try
            {
                int size = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, file.DangerousGetHandle(), ref size, null, 0);
                if (size is <= 0 or > 64) continue;
                var hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.DangerousGetHandle(), ref size, hash, 0)) continue;
                var info = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                if (info == IntPtr.Zero) { last = "not in any system catalog"; continue; }
                try
                {
                    var catalog = new CatalogInfo { Size = Marshal.SizeOf<CatalogInfo>() };
                    if (!CryptCATCatalogInfoFromContext(info, ref catalog, 0)) { last = "the catalog could not be read"; continue; }
                    if (Trust(path, file.DangerousGetHandle(), catalog.File, hash, admin) is { } problem) return problem;
                    var cms = new SignedCms();
                    cms.Decode(File.ReadAllBytes(catalog.File));
                    return Certificates.CheckSigner(cms, organization, out note) is { } signer ? $"catalog {Path.GetFileName(catalog.File)}: {signer}" : null;
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, info, 0); }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                return $"catalog unreadable: {ex.Message}";
            }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }
        return last ?? "no catalog signature";
    }

    private static string? Trust(string path, IntPtr handle, string catalogPath, byte[] hash, IntPtr admin)
    {
        var tag = Convert.ToHexString(hash);
        var member = new CatalogMember
        {
            Size = Marshal.SizeOf<CatalogMember>(),
            CatalogFilePath = catalogPath,
            MemberTag = tag,
            MemberFilePath = path,
            MemberFile = handle,
            CatalogAdmin = admin,
        };
        var memberPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CatalogMember>());
        var hashPtr = Marshal.AllocHGlobal(hash.Length);
        try
        {
            Marshal.Copy(hash, 0, hashPtr, hash.Length);
            member.Hash = hashPtr;
            member.HashSize = hash.Length;
            Marshal.StructureToPtr(member, memberPtr, false);
            var data = new TrustData
            {
                Size = Marshal.SizeOf<TrustData>(),
                UiChoice = 2, // WTD_UI_NONE
                UnionChoice = 2, // WTD_CHOICE_CATALOG
                Union = memberPtr,
                StateAction = 1, // WTD_STATEACTION_VERIFY
                ProvFlags = 0x1000 | 0x10, // cache-only URL retrieval, no revocation check: never the network
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            int result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            data.StateAction = 2; // WTD_STATEACTION_CLOSE
            _ = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            return result == 0 ? null : $"WinVerifyTrust refused the catalog signature (0x{result:X8})";
        }
        finally
        {
            Marshal.DestroyStructure<CatalogMember>(memberPtr);
            Marshal.FreeHGlobal(memberPtr);
            Marshal.FreeHGlobal(hashPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public int Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string File;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogMember
    {
        public int Size;
        public int CatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string CatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr Hash;
        public int HashSize;
        public IntPtr CatalogContext;
        public IntPtr CatalogAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public int Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public int UiChoice;
        public int RevocationChecks;
        public int UnionChoice;
        public IntPtr Union;
        public int StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public int ProvFlags;
        public int UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string? hashAlgorithm, IntPtr policy, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref int hashSize, byte[]? hash, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, int hashSize, int flags, IntPtr previous);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr info, int flags);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr info, ref CatalogInfo catalog, int flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
}
