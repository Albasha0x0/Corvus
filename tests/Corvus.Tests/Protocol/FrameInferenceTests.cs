using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Length-prefix framing inferred from recorded Send and OnReceive chunks.</summary>
public class FrameInferenceTests
{
    private static byte[] Frame(string text, bool big = true)
    {
        var body = System.Text.Encoding.ASCII.GetBytes(text);
        var prefix = BitConverter.GetBytes((uint)body.Length);
        if (big) Array.Reverse(prefix);
        return [.. prefix, .. body];
    }

    [Fact]
    public void A_sent_u32_big_endian_prefix_is_reported()
    {
        var chunks = new[] { new RecordedChunk(false, Frame("hello")), new RecordedChunk(false, Frame("frame two")) };
        var layout = FrameInference.Infer(chunks, received: false);
        Assert.NotNull(layout);
        Assert.Equal("[u32 big-endian payload length][payload]", layout.Describe());
        Assert.Equal(2, layout.Frames);
        Assert.Equal(0, layout.Buffered);
    }

    [Fact]
    public void A_frame_split_across_receives_is_buffered_until_complete()
    {
        var all = Frame("hello").Concat(Frame("second message")).ToArray();
        var chunks = new[] { new RecordedChunk(true, all[..7]), new RecordedChunk(true, all[7..14]), new RecordedChunk(true, all[14..]) };
        var layout = FrameInference.Infer(chunks, received: true);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Frames);
        Assert.Equal(2, layout.SplitReads);
        Assert.Equal(0, layout.Missing);
    }

    [Fact]
    public void A_trailing_open_frame_reports_its_buffered_and_missing_bytes()
    {
        var all = Frame("hello").Concat(Frame("unfinished frame")).ToArray();
        var layout = FrameInference.Infer([new RecordedChunk(true, all[..^6])], received: true);
        Assert.NotNull(layout);
        Assert.Equal(1, layout.Frames);
        Assert.Equal(all.Length - 9 - 6, layout.Buffered);
        Assert.Equal(6, layout.Missing);
    }

    [Fact]
    public void A_little_endian_prefix_that_counts_itself_is_distinguished()
    {
        byte[] Make(string t) => [(byte)(t.Length + 2), 0, .. System.Text.Encoding.ASCII.GetBytes(t)];
        var layout = FrameInference.Infer([new RecordedChunk(false, [.. Make("abc"), .. Make("defgh")])], received: false);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.PrefixBytes);
        Assert.False(layout.BigEndian);
        Assert.True(layout.LengthIncludesPrefix);
    }

    [Fact]
    public void A_zlib_header_in_every_payload_names_the_transform()
    {
        byte[] Packed(int n) => [0, 0, 0, (byte)(n + 2), 0x78, 0x9C, .. new byte[n]];
        var layout = FrameInference.Infer([new RecordedChunk(true, [.. Packed(4), .. Packed(6)])], received: true);
        Assert.NotNull(layout);
        Assert.Equal("zlib", layout.Transform);
    }

    [Fact]
    public void Bytes_without_a_length_prefix_report_no_layout()
    {
        Assert.Null(FrameInference.Infer([new RecordedChunk(true, [0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3])], received: true));
    }

    private static byte[] Prefixed(int width, byte[] body)
    {
        var p = new byte[width];
        for (var i = 0; i < width; i++) p[width - 1 - i] = (byte)(body.Length >> (8 * i));
        return [.. p, .. body];
    }

    private static byte[] Text(int n) => Enumerable.Repeat((byte)'A', n).ToArray();

    private static FrameLayout? InferOne(byte[] data, bool received) =>
        FrameInference.Infer([new RecordedChunk(received, data)], received);

    [Fact]
    public void A_u16_big_endian_prefix_with_payloads_over_255_bytes_is_not_read_as_u8()
    {
        var layout = InferOne([.. Prefixed(2, Text(261)), .. Prefixed(2, Text(300))], false);
        Assert.NotNull(layout);
        Assert.Equal("[u16 big-endian payload length][payload]", layout.Describe());
        Assert.Equal(2, layout.Frames);
    }

    [Fact]
    public void A_u8_prefix_is_reported_without_a_byte_order()
    {
        var layout = InferOne([.. Prefixed(1, Text(5)), .. Prefixed(1, Text(9)), .. Prefixed(1, Text(3))], false);
        Assert.NotNull(layout);
        Assert.Equal("[u8 payload length][payload]", layout.Describe());
    }

    [Fact]
    public void A_gzip_header_in_every_payload_names_the_transform()
    {
        byte[] Packed(int n) => Prefixed(4, [0x1F, 0x8B, .. new byte[n]]);
        var layout = InferOne([.. Packed(4), .. Packed(6)], true);
        Assert.NotNull(layout);
        Assert.Equal("gzip", layout.Transform);
    }

    [Fact]
    public void Payloads_with_different_headers_name_no_transform()
    {
        var layout = InferOne([.. Prefixed(4, [0x78, 0x9C, 1, 2]), .. Prefixed(4, [0x1F, 0x8B, 1, 2])], true);
        Assert.NotNull(layout);
        Assert.Null(layout.Transform);
    }

    [Fact]
    public void Empty_chunks_are_ignored()
    {
        var chunks = new[]
        {
            new RecordedChunk(false, []), new RecordedChunk(false, Frame("hello")),
            new RecordedChunk(false, []), new RecordedChunk(false, Frame("again")),
        };
        var layout = FrameInference.Infer(chunks, received: false);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Frames);
        Assert.Equal(0, layout.SplitReads);
    }

    [Fact]
    public void Chunks_of_the_other_direction_are_excluded()
    {
        var chunks = new[]
        {
            new RecordedChunk(false, Frame("hello")), new RecordedChunk(true, [1, 2, 3]),
            new RecordedChunk(false, Frame("again")),
        };
        var layout = FrameInference.Infer(chunks, received: false);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Frames);
        Assert.Equal(0, layout.Buffered);
    }

    [Fact]
    public void A_read_that_ends_on_a_frame_edge_is_not_split()
    {
        var chunks = new[] { new RecordedChunk(true, Frame("hello")), new RecordedChunk(true, Frame("again")) };
        var layout = FrameInference.Infer(chunks, received: true);
        Assert.NotNull(layout);
        Assert.Equal(0, layout.SplitReads);
    }

    [Fact]
    public void A_single_complete_frame_reports_no_layout()
    {
        Assert.Null(InferOne(Frame("hello"), false));
    }

    [Fact]
    public void Valid_frames_before_an_invalid_length_are_kept_and_the_stop_is_reported()
    {
        var layout = InferOne([.. Frame("hello"), .. Frame("second"), 0xFF, 0xFF, 0xFF, 0xFF, 1, 2], true);
        Assert.NotNull(layout);
        Assert.Equal(4, layout.PrefixBytes);
        Assert.Equal(2, layout.Frames);
        Assert.Equal(19, layout.ParsedBytes);
        Assert.Equal(6, layout.Buffered);
        Assert.True(layout.Stopped);
        Assert.Null(layout.Missing);
    }

    [Fact]
    public void A_stream_cut_inside_the_prefix_reports_the_missing_length_as_unknown()
    {
        var layout = InferOne([.. Frame("hello"), .. Frame("second"), 0, 0], true);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Buffered);
        Assert.Null(layout.Missing);
        Assert.False(layout.Stopped);
    }

    [Fact]
    public void A_zero_length_frame_is_counted_apart_from_the_frames()
    {
        var layout = InferOne([.. Frame("hello"), .. Frame(""), .. Frame("again")], false);
        Assert.NotNull(layout);
        Assert.Equal(3, layout.Frames);
        Assert.Equal(1, layout.EmptyFrames);
    }

    [Fact]
    public void Frames_coalesced_into_one_read_are_all_parsed_without_a_split()
    {
        var layout = InferOne([.. Frame("one"), .. Frame("two"), .. Frame("three")], true);
        Assert.NotNull(layout);
        Assert.Equal(3, layout.Frames);
        Assert.Equal(0, layout.SplitReads);
        Assert.Equal(0, layout.Buffered);
    }

    [Fact]
    public void A_read_that_completes_a_frame_and_starts_the_next_leaves_the_remainder_buffered()
    {
        var all = Frame("alpha").Concat(Frame("beta")).Concat(Frame("gamma frame")).ToArray();
        var cut = Frame("alpha").Length + Frame("beta").Length + 6;
        var layout = FrameInference.Infer(
            [new RecordedChunk(true, all[..5]), new RecordedChunk(true, all[5..cut])], received: true);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Frames);
        Assert.Equal(6, layout.Buffered);
        Assert.Equal(Frame("gamma frame").Length - 6, layout.Missing);
        Assert.Equal(1, layout.SplitReads);
    }

    [Fact]
    public void A_later_read_completes_a_buffered_frame()
    {
        var all = Frame("alpha").Concat(Frame("gamma frame")).ToArray();
        var cut = Frame("alpha").Length + 6;
        var layout = FrameInference.Infer(
            [new RecordedChunk(true, all[..cut]), new RecordedChunk(true, all[cut..])], received: true);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Frames);
        Assert.Equal(0, layout.Buffered);
        Assert.Equal(0, layout.Missing);
        Assert.Equal(1, layout.SplitReads);
    }

    [Fact]
    public void An_empty_frame_inside_a_coalesced_read_is_counted_and_not_split()
    {
        var layout = InferOne([.. Frame("one"), .. Frame(""), .. Frame("two")], true);
        Assert.NotNull(layout);
        Assert.Equal(3, layout.Frames);
        Assert.Equal(1, layout.EmptyFrames);
        Assert.Equal(0, layout.SplitReads);
        Assert.Equal(0, layout.Buffered);
    }

    [Fact]
    public void An_oversized_length_after_a_coalesced_frame_stops_with_the_remainder_buffered()
    {
        var layout = InferOne([.. Frame("one"), .. Frame("two"), 0xFF, 0xFF, 0xFF, 0xFF], true);
        Assert.NotNull(layout);
        Assert.Equal(2, layout.Frames);
        Assert.True(layout.Stopped);
        Assert.Equal(4, layout.Buffered);
    }
}
