namespace Corvus.Native.MachO;

public sealed partial class MachOFile
{
    /// <summary>Bytes before the load commands: the Mach header size.</summary>
    public long HeaderSize => Is64Bit ? 32 : 28;

    /// <summary>ncmds: the number of load commands.</summary>
    public uint CommandCount => view.U32(16);

    /// <summary>sizeofcmds: the total byte length of the load commands following the header.</summary>
    public uint SizeOfCommands => view.U32(20);

    /// <summary>The image uses LC_DYLD_CHAINED_FIXUPS (rebases and binds threaded through the pointers themselves).</summary>
    public bool HasChainedFixups => Fixups.Source == "chained fixups";
}
