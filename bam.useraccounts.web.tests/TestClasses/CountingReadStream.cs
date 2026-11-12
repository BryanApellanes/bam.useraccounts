namespace Bam.UserAccounts.Web.Tests.TestClasses;

/// <summary>
/// Wraps a request body and counts the bytes the endpoint reads from it, so a test can tell a
/// refusal on the declared length (nothing read) from one that read the body first.
/// </summary>
public sealed class CountingReadStream : Stream
{
    private readonly Stream _inner;
    private long _bytesRead;

    public CountingReadStream(Stream inner)
    {
        _inner = inner;
    }

    /// <summary>The bytes read through this stream so far.</summary>
    public long BytesRead => Interlocked.Read(ref _bytesRead);

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        Interlocked.Add(ref _bytesRead, read);
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        Interlocked.Add(ref _bytesRead, read);
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
}
