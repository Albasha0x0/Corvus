namespace Corvus.Tests;

/// <summary>An emulator as the fake adb plays it: devices, properties, packages, dumpsys, pulls, log, install and uninstall.</summary>
internal static class FakeDevice
{
    public const string Serial = "emulator-5554", Package = "com.example.app";

    public const string Dumpsys = """
        Activity Resolver Table:
          Non-Data Actions:
              android.intent.action.MAIN:
                1a2b3c com.example.app/.Main filter 4d5e6f

        Packages:
          Package [com.example.app] (5f1e2d):
            userId=10123
            pkg=Package{8a9b com.example.app}
            codePath=/data/app/~~AbC==/com.example.app-XyZ==
            resourcePath=/data/app/~~AbC==/com.example.app-XyZ==
            primaryCpuAbi=arm64-v8a
            secondaryCpuAbi=null
            versionCode=42 minSdk=24 targetSdk=34
            versionName=1.2
            flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]
            dataDir=/data/user/0/com.example.app
            timeStamp=2026-01-02 03:04:05
            firstInstallTime=2026-01-02 03:04:06
            lastUpdateTime=2026-01-03 04:05:06
            installerPackageName=com.android.vending
            requested permissions:
              android.permission.INTERNET
              android.permission.CAMERA
              android.permission.READ_EXTERNAL_STORAGE: restricted=true
            install permissions:
              android.permission.INTERNET: granted=true
            User 0: ceDataInode=12345 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false
              runtime permissions:
                android.permission.CAMERA: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
            User 10: ceDataInode=0 installed=false hidden=false suspended=false enabled=0
          Package [com.example.app] (ffff):
            userId=1

        Queries:
        """;

    /// <summary>Adds the emulator's answers to <paramref name="fake"/>; <paramref name="apk"/> is what pulling base.apk yields.</summary>
    public static FakeTool Configure(FakeTool fake, byte[] apk)
    {
        fake.On(@"^devices -l$", "List of devices attached\n" +
                                 $"{Serial}          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1\n" +
                                 "R58M123ABC          unauthorized usb:1-1 transport_id:2\n" +
                                 "* daemon started successfully\n" +
                                 "garbage\n\n");
        fake.On(@"shell getprop$", "[ro.build.version.sdk]: [34]\n[ro.build.version.release]: [14]\n[ro.product.cpu.abilist]: [arm64-v8a,armeabi-v7a]\n" +
                                   "[ro.build.fingerprint]: [google/sdk_gphone64_arm64/emu64a:14/UE1A/11:userdebug/dev-keys]\n[ro.kernel.qemu]: [1]\n" +
                                   "[ro.hardware]: [ranchu]\n[ro.debuggable]: [1]\n[ro.secure]: [1]\n[ro.product.model]: [sdk_gphone64_arm64]\n" +
                                   "[persist.sys.multiline]: [first\n");
        fake.On(@"pm list packages -f -U -i", $"package:/data/app/~~AbC==/{Package}-XyZ==/base.apk={Package}  uid:10123 installer=com.android.vending\n" +
                                              "package:/system/priv-app/Settings/Settings.apk=com.android.settings  uid:1000 installer=null\n");
        fake.On(@"dumpsys package com\.example\.app$", Dumpsys.Replace("\r\n", "\n"));
        fake.On(@"dumpsys package", "Packages:\n");
        fake.On(@"pm path com\.example\.app$", $"package:/data/app/~~AbC==/{Package}-XyZ==/base.apk\npackage:/data/app/~~AbC==/{Package}-XyZ==/split_config.arm64_v8a.apk\n");
        fake.On(@"pm path", "");
        fake.On(@"pull \S+base\.apk ", file: apk);
        fake.On(@"pull \S+split_config", file: ContainerFixtures.Zip(("AndroidManifest.xml", [0x03, 0x00, 0x08, 0x00])));
        fake.On(@"stat -c %F /data/local/tmp/dir$", "directory\n");
        fake.On(@"stat -c %F /data/local/tmp/missing", stderr: "stat: '/data/local/tmp/missing': No such file or directory\n", exit: 1);
        fake.On(@"stat -c %F ", "regular file\n");
        fake.On(@"pull /data/local/tmp/fail\.txt", stderr: "adb: error: failed to copy\n", exit: 1);
        fake.On(@"pull /data/local/tmp/\S+ ", file: "hello from the device\n"u8.ToArray());
        fake.On(@"logcat -d -v threadtime --pid=999", "01-02 03:04:05.678  999  999 I App: only pid\n");
        fake.On(@"logcat .*Flood:V", "01-02 03:04:05.678  1  1 W Flood: " + new string('x', 200) + "\n", repeat: 5_000);
        fake.On(@"logcat -d -v threadtime", "01-02 03:04:05.678  123  456 I ActivityManager: Start proc\n01-02 03:04:05.679  123  456 E App: boom\n");
        fake.On(@"install-multiple .*old\.apk", "Performing Incremental Install\nFailure [INSTALL_FAILED_VERSION_DOWNGRADE: Downgrade detected]\n", exit: 1);
        fake.On(@"install-multiple", "Success\n");
        fake.On(@"uninstall .*com\.missing", "Failure [DELETE_FAILED_INTERNAL_ERROR]\n", exit: 1);
        fake.On(@"uninstall", "Success\n");
        return fake;
    }

    private static readonly Lazy<FakeTool> SharedTool = new(() =>
    {
        var fake = Configure(new FakeTool(), AndroidSamples.Apk());
        LeakGuard.DeleteAtEnd(fake.Directory);
        return fake;
    });

    /// <summary>Environment for a test server: adb is the fake playing this emulator.</summary>
    public static IReadOnlyDictionary<string, string?> ServerEnvironment => new Dictionary<string, string?>
    {
        ["CORVUS_ADB"] = FakeTool.Executable,
        [FakeTool.ScriptVariable] = SharedTool.Value.ScriptPath,
        ["CORVUS_JAVA_DECOMPILER"] = "", // the JADX server is never found by a test server
    };
}
