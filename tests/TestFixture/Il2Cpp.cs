// Mimics the attributes Il2CppDumper injects into its DummyDll output.
namespace Il2CppDummyDll
{
    [AttributeUsage(AttributeTargets.All)]
    public class AddressAttribute : Attribute
    {
        public string? RVA;
        public string? Offset;
        public string? VA;
        public string? Slot;
    }

    [AttributeUsage(AttributeTargets.All)]
    public class FieldOffsetAttribute : Attribute
    {
        public string? Offset;
    }

    [AttributeUsage(AttributeTargets.All)]
    public class TokenAttribute : Attribute
    {
        public string? Token;
    }
}

namespace Fixture.Native
{
    using Il2CppDummyDll;

    [Token(Token = "0x2000010")]
    public class NativeThing
    {
        [FieldOffset(Offset = "0x10")]
        public int Counter;

        [Address(RVA = "0x1000", Offset = "0x400", VA = "0x180001000")]
        public void First() { }

        [Address(RVA = "0x1100", Offset = "0x500", VA = "0x180001100", Slot = "4")]
        public virtual void Second() { }

        // what Il2CppDumper writes for some generic methods without native code of their own
        [Address(RVA = "0xA5399800A5350", Offset = "0x0", VA = "0xA539B000A5350")]
        public static T Shared<T>(T value) => value;
    }
}
