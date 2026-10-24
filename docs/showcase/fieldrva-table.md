# Showcase: a crypto table in an array initializer

The question: where does a .NET crypto library keep the SHA-256 round constants, which code reads them, and are the
bytes in the file what the metadata says? The assembly is `BouncyCastle.Cryptography.dll` from the public NuGet package
[BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/2.6.2), read from the NuGet
packages folder after a restore.

The C# compiler stores `new uint[] { 0x428A2F98, ... }` as a FieldRVA field of `<PrivateImplementationDetails>`: raw
bytes in the image that `RuntimeHelpers.InitializeArray` copies at run time. Search for the first constant, then outline
the data field the hit names:

<!-- check: batch show=2,3 -->
```json
{"tool": "load_assembly", "args": {"path": "~/.nuget/packages/bouncycastle.cryptography/2.6.2/lib/net6.0/BouncyCastle.Cryptography.dll"}}
{"tool": "search_constants", "args": {"assembly": "BouncyCastle.Cryptography", "value": "0x428a2f98"}}
{"tool": "get_type_info", "args": {"assembly": "BouncyCastle.Cryptography", "type": "<PrivateImplementationDetails>::74EF7306E7452D6859B6463CE496B8DF30925F69E1B2969E1F3F34BBC9C6AF04", "limit": 4}}
```

<!-- check: output -->
```text
=== [2/3] search_constants
Occurrences of 0x428a2f98: 3 occurrences (showing 1-3):
  Org.BouncyCastle.Crypto.Digests.LongDigest::.cctor()  array initializer element [0] (high half) of ulong[] (data <sha256-1>) 1116352408  [BouncyCastle.Cryptography] 0x060039F4
  Org.BouncyCastle.Crypto.Digests.Sha224Digest::.cctor()  array initializer element [0] of uint[] (data <sha256-2>) 1116352408  [BouncyCastle.Cryptography] 0x06003AEF
  Org.BouncyCastle.Crypto.Digests.Sha256Digest::.cctor()  array initializer element [0] of uint[] (data <sha256-2>) 1116352408  [BouncyCastle.Cryptography] 0x06003B03
[End: 3 occurrences]
=== [3/3] get_type_info
internal static readonly __StaticArrayInitTypeSize=256 <sha256-2>
  full name: <PrivateImplementationDetails>::<sha256-2>   token: 0x04002760   assembly: BouncyCastle.Cryptography
  declared in: <PrivateImplementationDetails>
  initial data: 256 bytes at RVA 0x3F9498, file offset 0x3F7698 (bytes match), SHA-256 <sha256-2>
  read by Org.BouncyCastle.Crypto.Digests.Sha224Digest::.cctor() @IL_0008 0x06003AEF as uint[]
  read by Org.BouncyCastle.Crypto.Digests.Sha256Digest::.cctor() @IL_0008 0x06003B03 as uint[]
  as uint[64]: 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
16 16-byte rows (showing 1-4):
  0x0000  98 2f 8a 42 91 44 37 71 cf fb c0 b5 a5 db b5 e9  ./.B.D7q........
  0x0010  5b c2 56 39 f1 11 f1 59 a4 82 3f 92 d5 5e 1c ab  [.V9...Y..?..^..
  0x0020  98 aa 07 d8 01 5b 83 12 be 85 31 24 c3 7d 0c 55  .....[....1$.}.U
  0x0030  74 5d be 72 fe b1 de 80 a7 06 dc 9b 74 f1 9b c1  t].r........t...
[More: offset=4]
```

The outline joins the bytes to the code. The bytes at the file offset are checked against the metadata. The SHA-224
and SHA-256 static constructors both read the one shared field. The `newarr uint32` beside each read types the
elements, so the table reads as the 64 constants of FIPS 180-4, not a hex blob. The field's name is the SHA-256 of its
bytes, as the data line confirms. `offset` pages the 16-byte rows.
