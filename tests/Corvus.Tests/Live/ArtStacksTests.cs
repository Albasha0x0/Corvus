using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Mobile;

namespace Corvus.Tests;

/// <summary>Java stacks read from ART's thread dump, on a dump written here in the format ART 14 prints.</summary>
public sealed class ArtStacksTests
{
    private const string Dump = """

        ----- pid 4100 at 2026-10-25 12:19:41.921395900+0300 -----
        Cmd line: /system/bin/app_process64
        DALVIK THREADS (3):
        "main" prio=5 tid=1 Native
          | group="main" sCount=1 ucsCount=0 flags=1 obj=0x730f71c8 self=0x7a503a1e4f50
          | sysTid=4100 nice=0 cgrp=foreground sched=0/0 handle=0x7a51ed20d4f8
          native: #00 pc 0000a2c4  /system/lib64/liblog.so (__android_log_buf_write+20) (BuildId: 0123456789abcdef)
          native: #01 pc 00179ea3  /system/lib64/libandroid_runtime.so (android::android_util_Log_println_native+35)
          at android.util.Log.println_native(Native method)
          at android.util.Log.i(Log.java:192)
          at Ledger.balanceOf(Ledger.java:10)
          at Ledger.main(Ledger.java:4)

        "ReferenceQueueDaemon" daemon prio=5 tid=10 Waiting
          | group="system" sCount=1 ucsCount=0 flags=1 obj=0x16280d58 self=0x7a503a20b330
          | sysTid=4117 nice=4 cgrp=foreground sched=0/0 handle=0x7a4ec8a37cf0
          at java.lang.Object.wait(Native method)
          - waiting on <0x0c2e9a4f> (a java.lang.Class<java.lang.ref.ReferenceQueue>)
          at java.lang.Daemons$ReferenceQueueDaemon.runInternal(Daemons.java:239)

        "Signal Catcher" daemon prio=10 tid=4 Runnable
          | group="system" sCount=0 ucsCount=0 flags=0 obj=0x16280c80 self=0x7a503a2044a0
          | sysTid=4110 nice=-20 cgrp=foreground sched=0/0 handle=0x7a4ed4da0cf0

        Dumping registered class loaders
        #0 dalvik.system.PathClassLoader: [], parent #1
        #1 java.lang.BootClassLoader: [], no parent
        #2 dalvik.system.PathClassLoader: [/data/app/~~a1/com.ledger-b2/base.apk:/data/app/~~a1/com.ledger-b2/base.apk!classes2.dex], parent #1
        #3 dalvik.system.DexClassLoader: [/data/user/0/com.ledger/files/plugin.jar], parent #2
        Done dumping class loaders

        ----- end 4100 -----
        """;

    [Fact]
    public void The_thread_is_found_by_its_Linux_thread_id_with_its_Java_frames_innermost_first()
    {
        var main = ArtStacks.Of(Dump, 4100)!;
        Assert.Equal(("main", "Native"), (main.Name, main.State));
        Assert.Equal([("android.util.Log.println_native", "Native method"), ("android.util.Log.i", "Log.java:192"), ("Ledger.balanceOf", "Ledger.java:10"), ("Ledger.main", "Ledger.java:4")],
            main.Frames.Select(f => (f.Method, f.Source)));
    }

    [Fact]
    public void A_daemon_thread_keeps_its_frames_and_skips_its_lock_lines()
    {
        var daemon = ArtStacks.Of(Dump, 4117)!;
        Assert.Equal(("ReferenceQueueDaemon", "Waiting"), (daemon.Name, daemon.State));
        Assert.Equal(["java.lang.Object.wait", "java.lang.Daemons$ReferenceQueueDaemon.runInternal"], daemon.Frames.Select(f => f.Method));
    }

    [Fact]
    public void A_thread_without_Java_frames_is_found_with_none_and_an_unlisted_thread_is_null()
    {
        Assert.Empty(ArtStacks.Of(Dump, 4110)!.Frames);
        Assert.Null(ArtStacks.Of(Dump, 4101));
        Assert.Null(ArtStacks.Of("", 4100));
    }

    [Fact]
    public void The_class_loaders_name_each_package_once_with_multidex_entries_folded()
    {
        Assert.Equal(["/data/app/~~a1/com.ledger-b2/base.apk", "/data/user/0/com.ledger/files/plugin.jar"], ArtStacks.Of(Dump, 4100)!.ClassPath);
    }

    [Fact]
    public void A_frame_names_its_DEX_method_and_overloads_are_told_apart_by_line()
    {
        var b = new DexBuilder();
        var book = b.Class("Lcom/ledger/Ledger$Book;", source: "Ledger.java");
        var byCents = book.Method("post", "V", ["I"], 1, Asm.Nop(), Asm.Nop(), Asm.ReturnVoid());
        byCents.Lines.AddRange([(0, 10), (1, 11)]);
        var byText = book.Method("post", "V", ["Ljava/lang/String;"], 1, Asm.Nop(), Asm.Nop(), Asm.ReturnVoid());
        byText.Lines.AddRange([(0, 20), (2, 21)]);
        book.Method("total", "I", [], 1, Asm.Const4(0, 0), Asm.Return(0x0f, 0));
        using var dir = new TempDir();
        var path = dir.File("classes.dex");
        File.WriteAllBytes(path, b.Build());
        var index = DexIndex.Load(path, AnalysisLimits.Default, default);

        Assert.Equal(new DexFrameMatch("Lcom/ledger/Ledger$Book;->post(Ljava/lang/String;)V", 2, "classes.dex"),
            ArtStacks.Match(index, new("com.ledger.Ledger$Book.post", "Ledger.java:21")));
        Assert.Equal(0, ArtStacks.Match(index, new("com.ledger.Ledger$Book.post", "Ledger.java:10"))!.DexPc);
        // A single method matches without a line in its table.
        Assert.Equal(new DexFrameMatch("Lcom/ledger/Ledger$Book;->total()I", null, "classes.dex"), ArtStacks.Match(index, new("com.ledger.Ledger$Book.total", "Unknown Source")));
        Assert.Null(ArtStacks.Match(index, new("com.ledger.Ledger$Book.post", "Ledger.java:99")));
        Assert.Null(ArtStacks.Match(index, new("android.util.Log.i", "Log.java:192")));
    }
}
