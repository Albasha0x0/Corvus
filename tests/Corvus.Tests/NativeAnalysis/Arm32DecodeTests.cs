using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>
/// The A32 / T32 decoder on encodings taken from compiler output (Android armeabi-v7a and Linux ARM libraries), each
/// checked against an independent disassembler: text, length, control flow and register use.
/// </summary>
public class Arm32DecodeTests
{
    private static ArmInstruction Decode(bool thumb, string hex, uint address, bool inIt = false)
    {
        var bytes = Convert.FromHexString(hex);
        ArmInstruction i;
        if (thumb) Arm32Decode.Thumb(bytes, address, inIt, out i);
        else Arm32Decode.Arm(BitConverter.ToUInt32(bytes), address, out i);
        return i;
    }

    [Theory]
    [InlineData("F0B5", 0x10E54, "push   {r4, r5, r6, r7, lr}")]
    [InlineData("2DE90007", 0x10E58, "push.w {r8, r9, r10}")]
    [InlineData("32F06EE8", 0x10E72, "blx    0x42F50")]
    [InlineData("90B1", 0x10E76, "cbz    r0, 0x10E9E")]
    [InlineData("A0EB0A04", 0x10E78, "sub.w  r4, r0, r10")]
    [InlineData("40F08180", 0x10E88, "bne.w  0x10F8E")]
    [InlineData("00F00AF9", 0x10EA0, "bl     0x110B8")]
    [InlineData("0180", 0x10ECE, "strh   r1, [r0]")]
    [InlineData("47F22E31", 0x10EDC, "movw   r1, #0x732E")]
    [InlineData("C0F26F01", 0x10EE0, "movt   r1, #0x6F")]
    [InlineData("B9F1000F", 0x10EFA, "cmp.w  r9, #0")]
    [InlineData("15D0", 0x10EFE, "beq    0x10F2C")]
    [InlineData("A6B9", 0x10F00, "cbnz   r6, 0x10F2C")]
    [InlineData("1CBF", 0x10F24, "itt    ne")]
    [InlineData("34BF", 0x13E1A, "ite    lo")]
    [InlineData("BDE80007", 0x1106A, "pop.w  {r8, r9, r10}")]
    [InlineData("F0BD", 0x1106E, "pop    {r4, r5, r6, r7, pc}")]
    [InlineData("4FF48E73", 0x11122, "mov.w  r3, #0x11C")]
    [InlineData("D7F808A0", 0x11186, "ldr.w  r10, [r7, #8]")]
    [InlineData("04F10C06", 0x111B0, "add.w  r6, r4, #0xC")]
    [InlineData("DAE90623", 0x1121A, "ldrd   r2, r3, [r10, #0x18]")]
    [InlineData("C8E90601", 0x112E0, "strd   r0, r1, [r8, #0x18]")]
    [InlineData("CDF80080", 0x114F0, "str.w  r8, [sp]")]
    [InlineData("4BF9810A", 0x1183C, "vst1.32 {d16, d17}, [r11], r1")]
    [InlineData("04FB03F6", 0x11876, "mul    r6, r4, r3")]
    [InlineData("01F097BA", 0x1193A, "b.w    0x12E6C")]
    [InlineData("2DED0A8B", 0x11D6A, "vpush  {d8, d9, d10, d11, d12}")]
    [InlineData("DFEDC80B", 0x11DF4, "vldr   d16, [pc, #0x320]")]
    [InlineData("00FB0EC0", 0x1207E, "mla    r0, r0, lr, r12")]
    [InlineData("41E80020", 0x13B16, "strex  r0, r2, [r1]")]
    [InlineData("51E8000F", 0x13B1C, "ldrex  r0, [r1]")]
    [InlineData("BFF35B8F", 0x13B62, "dmb    ish")]
    [InlineData("82E80051", 0x1420E, "stm.w  r2, {r8, r12, lr}")]
    [InlineData("4FEA400A", 0x18934, "lsl.w  r10, r0, #1")]
    [InlineData("A9FB0001", 0x1A3C6, "umull  r0, r1, r9, r0")]
    [InlineData("DFE812F0", 0x1A548, "tbh    [pc, r2, lsl #1]")]
    [InlineData("ADF25C4D", 0x1B594, "subw   sp, sp, #0x45C")]
    [InlineData("B0FA80F0", 0x1D4E6, "clz    r0, r0")]
    [InlineData("DFE800F0", 0x1D816, "tbb    [pc, r0]")]
    [InlineData("58CE", 0x1E096, "ldm    r6, {r3, r4, r6}")]
    [InlineData("C4F34008", 0x27152, "ubfx   r8, r4, #1, #1")]
    [InlineData("F1EE10FA", 0x37766, "vmrs   apsr_nzcv, fpscr")]
    [InlineData("01EE100A", 0x37BE8, "vmov   s2, r0")]
    [InlineData("3CF9042F", 0x37D44, "ldrsh  r2, [r12, #4]!")]
    [InlineData("64F9EF0A", 0x31F8C, "vld1.64 {d16, d17}, [r4:128]")]
    [InlineData("B7EE001A", 0x328D6, "vmov.f32 s2, #1.000000e+00")]
    [InlineData("FEDE", 0x36426, "trap")]
    [InlineData("03A1", 0x1000, "adr    r1, 0x1010")]
    [InlineData("7944", 0x1000, "add    r1, pc")]
    [InlineData("1847", 0x1000, "bx     r3")]
    [InlineData("7047", 0x1000, "bx     lr")]
    public void Thumb_text_matches_reference(string hex, uint address, string text) =>
        Assert.Equal(text, Decode(true, hex, address).Format());

    [Theory]
    [InlineData("C0EF5000", 0x3164A, "vmov.i32 q8, #0")]
    [InlineData("24EFF4E1", 0x3D948, "vorr   q7, q10, q10")]
    [InlineData("10FFF2E1", 0x3D94C, "vbsl   q7, q8, q9")]
    [InlineData("F0EFE408", 0x3EA1A, "vext.64 q8, q8, q10, #1")]
    [InlineData("C8FF300A", 0x47F6C, "vmovl.u8 q8, d16")]
    [InlineData("40EF720D", 0x47FCC, "vmla.f32 q8, q0, q9")]
    [InlineData("F9FF6024", 0x47FD4, "vcgt.f32 q9, q8, #0")]
    [InlineData("F6FF2002", 0x47FE0, "vmovn.i32 d16, q8")]
    [InlineData("40EFC02F", 0x62FB8, "vmax.f32 q9, q8, q0")]
    [InlineData("C7FF3F0B", 0x632CC, "vbic.i16 d16, #0xFF00")]
    [InlineData("F8FF7040", 0x63EB8, "vshr.u32 q10, q8, #8")]
    [InlineData("F0FFE225", 0x662B4, "vmvn   q9, q9")]
    [InlineData("48FFF081", 0x66A26, "veor   q12, q12, q8")]
    [InlineData("F3FF7861", 0x67BE4, "vsra.u32 q11, q12, #0xD")]
    [InlineData("F4FFA308", 0x75C4E, "vtbl.8 d16, {d20}, d19")]
    [InlineData("F6FF2003", 0x246B1A, "vshll.i16 q8, d16, #0x10")]
    [InlineData("D1FFA00C", 0x276446, "vmull.u16 q8, d17, d16")]
    [InlineData("CAFFADE1", 0x2D4B82, "vaddw.u8 q15, q13, d29")]
    [InlineData("F2FF6A62", 0x2E34D0, "vqmovun.s16 d22, q13")]
    [InlineData("9DFF2D48", 0x2F490C, "vmlal.u16 q2, d13, d29")]
    [InlineData("D0EF7C78", 0x2FA7E2, "vrshrn.i32 d23, q14, #0x10")]
    [InlineData("85EE901B", 0x3D938, "vdup.32 d21, r1")]
    public void Neon_text_matches_reference(string hex, uint address, string text) =>
        Assert.Equal(text, Decode(true, hex, address).Format());

    // ARMv8 crypto: A32 words (little-endian bytes) and the T32 form of the same instruction
    [Theory]
    [InlineData(false, "0003B0F3", "aese.8 q0, q0")]
    [InlineData(true, "B0FF4003", "aesd.8 q0, q0")]
    [InlineData(false, "8003B0F3", "aesmc.8 q0, q0")]
    [InlineData(true, "F0FFE203", "aesimc.8 q8, q9")]
    [InlineData(false, "C002B9F3", "sha1h.32 q0, q0")]
    [InlineData(true, "BAFF8003", "sha1su1.32 q0, q0")]
    [InlineData(false, "C003BAF3", "sha256su0.32 q0, q0")]
    [InlineData(true, "00EF400C", "sha1c.32 q0, q0, q0")]
    [InlineData(false, "400C10F2", "sha1p.32 q0, q0, q0")]
    [InlineData(true, "60EF682C", "sha1m.32 q9, q0, q12")]
    [InlineData(false, "400C30F2", "sha1su0.32 q0, q0, q0")]
    [InlineData(true, "00FF400C", "sha256h.32 q0, q0, q0")]
    [InlineData(false, "400C10F3", "sha256h2.32 q0, q0, q0")]
    [InlineData(true, "20FF400C", "sha256su1.32 q0, q0, q0")]
    [InlineData(false, "A10EE0F2", "vmull.p64 q8, d16, d17")]
    [InlineData(true, "E0EFA10E", "vmull.p64 q8, d16, d17")]
    [InlineData(true, "BAFF0003", "vshll.i32 q0, d0, #0x20")]
    public void Crypto_text_matches_reference(bool thumb, string hex, string text)
    {
        var i = Decode(thumb, hex, 0x1000);
        Assert.Equal(text, System.Text.RegularExpressions.Regex.Replace(i.Format(), " +", " "));
        Assert.Equal((ArmFlow.Next, 0u, 0u), (i.Flow, (uint)i.Reads, (uint)i.Writes));
    }

    [Theory]
    [InlineData("F04F2DE9", 0x10000, "push   {r4, r5, r6, r7, r8, r9, r10, r11, lr}")]
    [InlineData("F08FBDE8", 0x10000, "pop    {r4, r5, r6, r7, r8, r9, r10, r11, pc}")]
    [InlineData("10009FE5", 0x10000, "ldr    r0, [pc, #0x10]")]
    [InlineData("00F19FE7", 0x10000, "ldr    pc, [pc, r0, lsl #2]")]
    [InlineData("00F18F90", 0x10000, "addls  pc, pc, r0, lsl #2")]
    [InlineData("1EFF2F01", 0x10000, "bxeq   lr")]
    [InlineData("33FF2FE1", 0x10000, "blx    r3")]
    [InlineData("000000FB", 0x10000, "blx    0x1000A")]
    [InlineData("100000EB", 0x10000, "bl     0x10048")]
    [InlineData("781645E3", 0x10000, "movt   r1, #0x5678")]
    [InlineData("D820C0E1", 0x10000, "ldrd   r2, r3, [r0, #8]")]
    [InlineData("902183E0", 0x10000, "umull  r2, r3, r0, r1")]
    [InlineData("10F113E7", 0x10000, "sdiv   r3, r0, r1")]
    [InlineData("700F1DEE", 0x10000, "mrc    p15, #0, r0, c13, c0, #3")]
    [InlineData("020B9FED", 0x10000, "vldr   d0, [pc, #8]")]
    [InlineData("0001A0E1", 0x10000, "lsl    r0, r0, #2")]
    [InlineData("04F09DE4", 0x10000, "pop    {pc}")]
    [InlineData("08F0BCE5", 0x10000, "ldr    pc, [r12, #8]!")]
    [InlineData("100B51EC", 0x10000, "vmov   r0, r1, d0")]
    [InlineData("C00AB7EE", 0x10000, "vcvt.f64.f32 d0, s0")]
    [InlineData("FEDEFFE7", 0x10000, "trap")]
    [InlineData("05C68FE2", 0x2F670, "adr    r12, 0x52F678")]
    public void Arm_text_matches_reference(string hex, uint address, string text) =>
        Assert.Equal(text, Decode(false, hex, address).Format());

    [Fact]
    public void Flow_and_targets()
    {
        // BLX from Thumb lands word-aligned in ARM state; BL keeps the state; BLX from ARM sets the halfword bit
        var blx = Decode(true, "32F06EE8", 0x10E72);
        Assert.Equal((ArmFlow.Call, 0x42F50u, false), (blx.Flow, blx.Target, blx.TargetThumb));
        var bl = Decode(true, "00F00AF9", 0x10EA0);
        Assert.Equal((ArmFlow.Call, true), (bl.Flow, bl.TargetThumb));
        var armBlx = Decode(false, "000000FB", 0x10000);
        Assert.Equal((0x1000Au, true), (armBlx.Target, armBlx.TargetThumb));

        Assert.Equal(ArmFlow.Return, Decode(true, "F0BD", 0).Flow);
        Assert.Equal(ArmFlow.Return, Decode(true, "7047", 0).Flow);
        Assert.Equal(ArmFlow.IndirectJump, Decode(true, "1847", 0).Flow);
        Assert.Equal(ArmFlow.IndirectJump, Decode(true, "DFE800F0", 0).Flow);
        Assert.Equal(ArmFlow.IndirectCall, Decode(false, "33FF2FE1", 0).Flow);
        Assert.Equal(ArmFlow.Return, Decode(false, "0EF0A0E1", 0).Flow);
        Assert.Equal(ArmFlow.Return, Decode(false, "04F09DE4", 0).Flow);
        Assert.Equal(ArmFlow.IndirectJump, Decode(false, "00F19FE7", 0).Flow);
        Assert.Equal(ArmFlow.Trap, Decode(true, "FEDE", 0).Flow);
        Assert.Equal(ArmFlow.Trap, Decode(true, "00BE", 0).Flow);

        var cond = Decode(false, "1EFF2F01", 0);
        Assert.True(cond.IsConditional);
        Assert.Equal(ArmFlow.Return, cond.Flow);
        var beq = Decode(true, "15D0", 0x10EFE);
        Assert.Equal((ArmFlow.Jump, (byte)0, 0x10F2Cu), (beq.Flow, beq.Cond, beq.Target));
    }

    [Fact]
    public void Register_use()
    {
        var pop = Decode(true, "F0BD", 0);
        Assert.Equal(0x80F0 | 1 << 13, pop.Writes);
        var push = Decode(false, "F04F2DE9", 0);
        Assert.Equal(0x4FF0 | 1 << 13, push.Reads);
        var ldrd = Decode(true, "DAE90623", 0);
        Assert.Equal(0b1100, ldrd.Writes);
        Assert.Equal(1 << 10, ldrd.Reads);
        var mla = Decode(true, "00FB0EC0", 0);
        Assert.Equal((1 << 0 | 1 << 14 | 1 << 12, 1), (mla.Reads, (int)mla.Writes));
        var wb = Decode(true, "3CF9042F", 0);
        Assert.Equal(1 << 2 | 1 << 12, wb.Writes);
        Assert.Equal((4, true), (Decode(true, "D7F808A0", 0).AccessSize, Decode(true, "D7F808A0", 0).Loads));
    }

    [Fact]
    public void It_blocks()
    {
        var it = Decode(true, "34BF", 0);
        Assert.Equal(("ite", 2), (it.Mnemonic, Arm32Decode.ItCount(it.ItMask)));
        Assert.Equal((byte)3, Arm32Decode.ItCondition(it.ItFirst, it.ItMask, 0));
        Assert.Equal((byte)2, Arm32Decode.ItCondition(it.ItFirst, it.ItMask, 1));
        // 16-bit data processing sets the flags outside an IT block only
        Assert.Equal("movs   r0, #1", Decode(true, "0120", 0).Format());
        var inside = Decode(true, "0120", 0, inIt: true);
        Assert.False(inside.SetsFlags);
        Assert.Equal("mov    r0, #1", inside.Format());
    }

    [Fact]
    public void Undecodable_encodings_are_invalid()
    {
        Assert.False(Decode(true, "FFF7", 0).IsValid);           // half of a 32-bit encoding
        Assert.Equal("nop", Decode(true, "00BF", 0).Mnemonic);
        Assert.False(Decode(false, "F0F0F0F6", 0).IsValid);       // unallocated media space
        Assert.Equal("simd", Decode(false, "100F00F3", 0).Mnemonic); // NEON data processing outside the decoded classes: valid, no operands
        Assert.Equal(2, Arm32Decode.ThumbLength(0xBF00));
        Assert.Equal(4, Arm32Decode.ThumbLength(0xF000));
    }
}
