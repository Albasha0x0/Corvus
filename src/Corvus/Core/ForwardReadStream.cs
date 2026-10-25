namespace Corvus.Core;

/// <summary>
/// A read-only stream read front to back: seeking, writing and setting the length throw <see cref="NotSupportedException"/>,
/// and so do <see cref="Length"/> and <see cref="Position"/> unless a subclass knows them.
/// </summary>
internal abstract class ForwardReadStream : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
