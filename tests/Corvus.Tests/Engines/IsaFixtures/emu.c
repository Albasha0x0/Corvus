/* Integer routines for the built-in emulator tests, compiled at -O2 for x86-64, x86 and AArch64 (build.ps1). */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;

u32 fnv1a(const char *s)
{
    u32 h = 0x811C9DC5u;
    while (*s) h = (h ^ (u8)*s++) * 0x01000193u;
    return h;
}

void xor_decode(u8 *dst, const u8 *src, u32 n, u8 key)
{
    for (u32 i = 0; i < n; i++) dst[i] = src[i] ^ (u8)(key + i);
}

u32 crc32(const u8 *p, u32 n)
{
    u32 c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}

/* 64-bit division needs runtime helpers on x86. */
#if !defined(__i386__)
u64 mix64(u64 a, u64 b)
{
    u64 r = a * b;
    r ^= a / (b | 1);
    r += (a << 13) | (a >> 51);
    r -= (u64)((i64)b >> 7);
    r += (u64)__builtin_popcountll(a) + (u64)__builtin_clzll(b | 1) + (u64)__builtin_ctzll(a | 0x8000000000000000ull);
    return r;
}

i64 sdiv_mod(i64 a, i64 b)
{
    return a / b * 1000 + a % b;
}
#endif

int sum_sorted(int *a, int n)
{
    for (int i = 1; i < n; i++) {
        int v = a[i], j = i - 1;
        while (j >= 0 && a[j] > v) { a[j + 1] = a[j]; j--; }
        a[j + 1] = v;
    }
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i] * (i + 1);
    return s;
}

static int b64(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

u32 b64_decode(u8 *out, const char *in)
{
    u32 n = 0, acc = 0;
    int bits = 0;
    for (; *in && *in != '='; in++) {
        int v = b64(*in);
        if (v < 0) continue;
        acc = acc << 6 | (u32)v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[n++] = (u8)(acc >> bits); }
    }
    return n;
}

u32 lookup(int k)
{
    switch (k) {
    case 0: return 0x1111;
    case 1: return 0x2345;
    case 2: return 0x3f00;
    case 3: return 0x4;
    case 4: return 0x55aa;
    case 5: return 0x6060;
    case 6: return 0x7007;
    case 7: return 0x8888;
    default: return 0xdead;
    }
}

struct record { u64 id; u32 flags; u32 size; u64 a, b, c, d; };

u64 copy_record(struct record *d, const struct record *s)
{
    *d = *s;
    d->flags |= 0x80;
    return d->a + d->d + d->size;
}

void _start(void)
{
    for (;;) {}
}
