using System.Security.Cryptography;

namespace Corvus.Services.Simplify;

/// <summary>A DES or AES algorithm object with the key, IV, mode and padding set on it; a generated key or IV is never read.</summary>
internal sealed class CipherObject(bool des) : HeapObject
{
    public bool Des { get; } = des;
    public byte[]? Key { get; set; }
    public byte[]? IV { get; set; }
    public CipherMode Mode { get; set; } = CipherMode.CBC;
    public PaddingMode Padding { get; set; } = PaddingMode.PKCS7;
    public int BlockSize => Des ? 64 : 128;
}

/// <summary>An encryptor or decryptor: what the algorithm object held when it was created, fixed from then on.</summary>
internal sealed class TransformObject(bool des, bool encrypt, byte[] key, byte[]? iv, CipherMode mode, PaddingMode padding) : HeapObject
{
    public bool Des { get; } = des;
    public bool Encrypt { get; } = encrypt;
    public byte[] Key { get; } = key;
    public byte[]? IV { get; } = iv;
    public CipherMode Mode { get; } = mode;
    public PaddingMode Padding { get; } = padding;
}

internal sealed partial class IlEvaluator
{
    private const string Crypto = "System.Security.Cryptography";

    /// <summary>The algorithm classes modelled, by name, and whether each is DES.</summary>
    private static readonly (string Type, bool Des)[] Ciphers =
    [
        ("DES", true), ("DESCryptoServiceProvider", true), ("Aes", false), ("AesManaged", false), ("AesCryptoServiceProvider", false),
        ("Rijndael", false), ("RijndaelManaged", false),
    ];

    /// <summary>DES and AES in CBC or ECB mode, deterministic given key, IV, padding and input; Rijndael with 128-bit blocks only;
    /// encryption with ISO 10126 padding (random fill) is not modelled.</summary>
    private static void AddCrypto(Action<string, string, string, string, Func<IlEvaluator, object?[], object?>> add)
    {
        const string I = "System.Int32", BA = "System.Byte[]", SA = Crypto + ".SymmetricAlgorithm", V = "System.Void";
        foreach (var (name, des) in Ciphers)
        {
            string type = $"{Crypto}.{name}";
            if (name is "DES" or "Aes" or "Rijndael") add(type, type, "Create", "", (e, _) => e.NewCipher(des));
            else add(V, type, ".ctor", "", (e, _) => e.NewCipher(des));
        }
        foreach (var owner in Ciphers.Select(c => $"{Crypto}.{c.Type}").Prepend(SA))
        {
            add(V, owner, "set_Key", BA, (e, a) => e.SetCipher(a[0], c => c.Key = Bytes(a[1]).ToArray()));
            add(V, owner, "set_IV", BA, (e, a) => e.SetCipher(a[0], c => c.IV = Bytes(a[1]).ToArray()));
            add(BA, owner, "get_Key", "", (e, a) => e.NewArray(Cipher(a[0]).Key?.ToArray() ?? throw Generated("key")));
            add(BA, owner, "get_IV", "", (e, a) => e.NewArray(Cipher(a[0]).IV?.ToArray() ?? throw Generated("IV")));
            add(V, owner, "set_Mode", $"{Crypto}.CipherMode", (e, a) => e.SetCipher(a[0], c => c.Mode = (CipherMode)I4(a[1])));
            add($"{Crypto}.CipherMode", owner, "get_Mode", "", (_, a) => (int)Cipher(a[0]).Mode);
            add(V, owner, "set_Padding", $"{Crypto}.PaddingMode", (e, a) => e.SetCipher(a[0], c => c.Padding = (PaddingMode)I4(a[1])));
            add($"{Crypto}.PaddingMode", owner, "get_Padding", "", (_, a) => (int)Cipher(a[0]).Padding);
            add(I, owner, "get_BlockSize", "", (_, a) => Cipher(a[0]).BlockSize);
            add(V, owner, "set_BlockSize", I, (e, a) => e.SetCipher(a[0], c =>
            {
                if (I4(a[1]) != c.BlockSize) throw Bail(FallbackReason.UnsupportedValue, $"a block size of {I4(a[1])} bits");
            }));
            add(V, owner, "set_KeySize", I, (e, a) => e.SetCipher(a[0], c =>
            {
                // A new key size generates a new (random) key.
                if (c.Key == null || c.Key.Length * 8 != I4(a[1])) c.Key = null;
            }));
            add($"{Crypto}.ICryptoTransform", owner, "CreateDecryptor", "", (e, a) => e.NewTransform(Cipher(a[0]), false, Cipher(a[0]).Key, Cipher(a[0]).IV));
            add($"{Crypto}.ICryptoTransform", owner, "CreateEncryptor", "", (e, a) => e.NewTransform(Cipher(a[0]), true, Cipher(a[0]).Key, Cipher(a[0]).IV));
            add($"{Crypto}.ICryptoTransform", owner, "CreateDecryptor", $"{BA},{BA}", (e, a) => e.NewTransform(Cipher(a[0]), false, Bytes(a[1]), a[2] == null ? null : Bytes(a[2])));
            add($"{Crypto}.ICryptoTransform", owner, "CreateEncryptor", $"{BA},{BA}", (e, a) => e.NewTransform(Cipher(a[0]), true, Bytes(a[1]), a[2] == null ? null : Bytes(a[2])));
            add(V, owner, "Clear", "", (_, a) => { Cipher(a[0]); return null; });
        }
        add(BA, $"{Crypto}.ICryptoTransform", "TransformFinalBlock", $"{BA},{I},{I}", (e, a) =>
            e.NewArray(Transform(Of<TransformObject>(a[0], "an ICryptoTransform"), Bytes(a[1]), I4(a[2]), I4(a[3]))));
        add(I, $"{Crypto}.ICryptoTransform", "get_InputBlockSize", "", (_, a) => Of<TransformObject>(a[0], "an ICryptoTransform").Des ? 8 : 16);
        add(I, $"{Crypto}.ICryptoTransform", "get_OutputBlockSize", "", (_, a) => Of<TransformObject>(a[0], "an ICryptoTransform").Des ? 8 : 16);
        add(V, "System.IDisposable", "Dispose", "", (_, a) => (a[0] is Pointer p ? p.Get() : a[0]) is CipherObject or TransformObject
            ? null
            : throw Bail(FallbackReason.UnsupportedCall, "calls System.IDisposable::Dispose() on an object the interpreter does not model"));
    }

    /// <summary>A type test of an algorithm object; only base types answer, since the concrete class differs between frameworks.</summary>
    private static bool IsAlgorithmType(dnlib.DotNet.TypeSig type) => type.FullName is $"{Crypto}.SymmetricAlgorithm" or "System.IDisposable" or "System.Object"
        ? true
        : throw Bail(FallbackReason.UnsupportedValue, $"type test of an algorithm object against {type.FullName}");

    private CipherObject NewCipher(bool des)
    {
        Allocate(64);
        return new CipherObject(des) { Shared = _cctorDepth > 0 };
    }

    private static CipherObject Cipher(object? v) => Of<CipherObject>(v, "a DES or AES algorithm object");

    private object? SetCipher(object? v, Action<CipherObject> set)
    {
        var c = Cipher(v);
        RequireMutable(c);
        set(c);
        return null;
    }

    private static EvaluationBailout Generated(string what) =>
        Bail(FallbackReason.ExternalIo, $"reads the {what} the algorithm object generated, which differs between runs");

    private TransformObject NewTransform(CipherObject c, bool encrypt, byte[]? key, byte[]? iv)
    {
        if (key == null) throw Generated("key");
        if (iv == null && c.Mode != CipherMode.ECB) throw Generated("IV");
        if (c.Mode is not (CipherMode.CBC or CipherMode.ECB)) throw Bail(FallbackReason.UnsupportedValue, $"cipher mode {c.Mode}");
        if (encrypt && c.Padding == PaddingMode.ISO10126) throw Bail(FallbackReason.ExternalIo, "ISO 10126 padding fills with random bytes");
        Allocate(64 + key.Length + (iv?.Length ?? 0));
        return new TransformObject(c.Des, encrypt, key.ToArray(), iv?.ToArray(), c.Mode, c.Padding) { Shared = _cctorDepth > 0 };
    }

    /// <summary>TransformFinalBlock, computed by the framework's own implementation of the algorithm.</summary>
    private static byte[] Transform(TransformObject t, byte[] input, int offset, int count)
    {
        if (offset < 0 || count < 0 || offset > input.Length - count) throw Bail(FallbackReason.RuntimeError, "TransformFinalBlock outside the buffer (ArgumentException)");
        try
        {
            using SymmetricAlgorithm algorithm = t.Des ? DES.Create() : Aes.Create();
            algorithm.Mode = t.Mode;
            algorithm.Padding = t.Padding;
            // ECB ignores the IV.
            var iv = t.IV ?? new byte[algorithm.BlockSize / 8];
            using var transform = t.Encrypt ? algorithm.CreateEncryptor(t.Key, iv) : algorithm.CreateDecryptor(t.Key, iv);
            return transform.TransformFinalBlock(input, offset, count);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw Bail(FallbackReason.RuntimeError, $"the transform throws {ex.GetType().Name} ({ex.Message})");
        }
    }
}
