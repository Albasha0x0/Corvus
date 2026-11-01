using Corvus.Native.Providers;
using Xunit;

namespace Corvus.Tests;

public class LinuxSandboxTests
{
    private const string Status = "Name:\tcorvus\nNoNewPrivs:\t1\nSeccomp:\t0\n";
    private const string Limits = "Limit                     Soft Limit           Hard Limit           Units\n" +
        "Max cpu time              unlimited            unlimited            seconds\n" +
        "Max core file size        0                    unlimited            bytes\n" +
        "Max data size             1073741824           unlimited            bytes\n";

    [Fact]
    public void The_no_new_privs_flag_is_read_from_the_status_text()
    {
        Assert.True(LinuxSandbox.NoNewPrivsOf(Status));
        Assert.False(LinuxSandbox.NoNewPrivsOf("NoNewPrivs:\t0\n"));
    }

    [Fact]
    public void A_status_without_the_flag_is_unknown_not_off()
    {
        Assert.Null(LinuxSandbox.NoNewPrivsOf("Name:\tcorvus\n"));
        Assert.Contains("no_new_privs unknown", LinuxSandbox.Read("Name:\tcorvus\n", Limits, "unsupported").Describe());
    }

    [Fact]
    public void The_soft_core_limit_is_read_and_unlimited_is_negative()
    {
        Assert.Equal(0, LinuxSandbox.SoftLimitOf(Limits, "Max core file size"));
        Assert.Equal(-1, LinuxSandbox.SoftLimitOf(Limits, "Max cpu time"));
        Assert.Null(LinuxSandbox.SoftLimitOf(Limits, "Max open files"));
    }

    [Fact]
    public void The_applied_settings_are_described_on_one_line()
    {
        Assert.Equal("no_new_privs on, landlock abi 4, special files refused, core dump limit 0, data limit 1073741824",
            LinuxSandbox.Read(Status, Limits, "abi 4, special files refused").Describe());
    }

    [Fact]
    public void An_unlimited_data_row_is_described_as_unlimited()
    {
        var limits = "Max data size             unlimited            unlimited            bytes\n";
        Assert.EndsWith("data limit unlimited", LinuxSandbox.Read(Status, limits, "unsupported").Describe());
    }

    [Fact]
    public void A_limits_text_without_a_data_row_describes_the_data_limit_as_unknown()
    {
        var limits = "Max core file size        0                    unlimited            bytes\n";
        Assert.EndsWith("data limit unknown", LinuxSandbox.Read(Status, limits, "unsupported").Describe());
    }

    [Fact]
    public void The_handled_mask_covers_only_char_sock_fifo_and_block_creation()
    {
        Assert.Equal((1UL << 6) | (1UL << 9) | (1UL << 10) | (1UL << 11), LinuxSandbox.HandledSpecialFiles);
    }

    [Fact]
    public void A_failed_landlock_outcome_is_described_unchanged()
    {
        Assert.Contains("landlock failed: errno 13,", LinuxSandbox.Read(Status, Limits, "failed: errno 13").Describe());
    }
}
