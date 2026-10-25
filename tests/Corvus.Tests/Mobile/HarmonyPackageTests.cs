using System.IO.Compression;
using System.Text;
using Corvus.Core.Ark;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>HarmonyOS modules and bundles: module.json and config.json, abilities, permissions, bytecode and native libraries.</summary>
public sealed class HarmonyPackageTests
{
    private const string StageProfile = """
        {
          "app": { "bundleName": "com.example.ledger", "versionCode": 1000002, "versionName": "1.0.2", "minAPIVersion": 12, "targetAPIVersion": 14 },
          "module": {
            "name": "entry", "type": "entry", "deviceTypes": ["phone", "tablet"],
            "abilities": [
              { "name": "EntryAbility", "srcEntry": "./ets/entryability/EntryAbility.ets", "exported": true,
                "skills": [ { "entities": ["entity.system.home"], "actions": ["action.system.home"] },
                            { "actions": ["ohos.want.action.viewData"], "uris": [ { "scheme": "https", "host": "ledger.example.com", "path": "open" } ] } ] },
              { "name": "DetailAbility", "srcEntry": "./ets/detail/DetailAbility.ets" }
            ],
            "extensionAbilities": [
              { "name": "SyncService", "type": "service", "srcEntry": "./ets/sync/SyncService.ets", "exported": false, "permissions": ["ohos.permission.KEEP_BACKGROUND_RUNNING"] }
            ],
            "requestPermissions": [
              { "name": "ohos.permission.INTERNET" },
              { "name": "ohos.permission.CAMERA", "reason": "$string:camera_reason", "usedScene": { "abilities": ["EntryAbility"], "when": "inuse" } }
            ]
          }
        }
        """;

    private const string FaProfile = """
        {
          "app": { "bundleName": "com.example.legacy", "version": { "code": 7, "name": "0.7" }, "apiVersion": { "compatible": 7, "target": 8 } },
          "deviceConfig": {},
          "module": {
            "package": "com.example.legacy.entry", "deviceType": ["phone"],
            "distro": { "moduleName": "entry", "moduleType": "entry" },
            "abilities": [ { "name": ".MainAbility", "type": "page", "srcPath": "MainAbility", "visible": true } ],
            "reqPermissions": [ { "name": "ohos.permission.INTERNET" } ]
          }
        }
        """;

    internal static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var m = new MemoryStream();
        using (var z = new ZipArchive(m, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, data) in entries)
            {
                using var s = z.CreateEntry(name).Open();
                s.Write(data);
            }
        return m.ToArray();
    }

    internal static byte[] StageModule(byte[] abc) => Zip(("module.json", Encoding.UTF8.GetBytes(StageProfile)), ("ets/modules.abc", abc),
        ("libs/arm64-v8a/libledger.so", [0x7F, (byte)'E', (byte)'L', (byte)'F']), ("resources.index", [1, 2, 3]));

    [Fact]
    public void A_stage_module_names_its_bundle_abilities_permissions_bytecode_and_libraries()
    {
        var found = new List<string>();
        var p = new HarmonyPackage(new MemoryStream(StageModule([1, 2, 3])), 1 << 20, (path, _) => found.Add(path));
        var m = Assert.Single(p.Modules);
        Assert.Equal(("stage", "com.example.ledger", "1.0.2", 1000002L, 12, 14, "entry", "entry"), (m.Model, m.Bundle, m.VersionName, m.VersionCode, m.MinApi, m.TargetApi, m.Name, m.Type));
        Assert.Equal(["phone", "tablet"], m.DeviceTypes);
        var entry = m.Abilities[0];
        Assert.Equal(("EntryAbility", "page", true), (entry.Name, entry.Type, entry.Exported));
        Assert.Equal(["action.system.home", "ohos.want.action.viewData"], entry.Actions);
        Assert.Equal(["https://ledger.example.com/open"], entry.Uris);
        Assert.False(m.Abilities[1].Exported);
        Assert.Equal(("SyncService", "service"), (m.Abilities[2].Name, m.Abilities[2].Type));
        Assert.Equal(["ohos.permission.KEEP_BACKGROUND_RUNNING"], m.Abilities[2].Permissions);
        Assert.Equal([new HarmonyPermission("ohos.permission.INTERNET", null, null), new HarmonyPermission("ohos.permission.CAMERA", "$string:camera_reason", "EntryAbility, inuse")], m.Permissions);
        Assert.Equal(["ets/modules.abc"], m.Bytecode);
        Assert.Equal(["libs/arm64-v8a/libledger.so"], m.NativeLibraries);
        Assert.Equal(["ets/modules.abc"], found);
        Assert.Empty(p.Issues);
    }

    [Fact]
    public void An_FA_module_reads_its_versions_from_config_json()
    {
        var hap = Zip(("config.json", Encoding.UTF8.GetBytes(FaProfile)), ("assets/js/MainAbility/app.abc", [1]));
        var m = Assert.Single(new HarmonyPackage(new MemoryStream(hap), 1 << 20).Modules);
        Assert.Equal(("FA", "com.example.legacy", "0.7", 7L, 7, 8, "entry", "entry"), (m.Model, m.Bundle, m.VersionName, m.VersionCode, m.MinApi, m.TargetApi, m.Name, m.Type));
        Assert.Equal((".MainAbility", "page", "MainAbility", true), (m.Abilities[0].Name, m.Abilities[0].Type, m.Abilities[0].SrcEntry, m.Abilities[0].Exported));
        Assert.Equal(["assets/js/MainAbility/app.abc"], m.Bytecode);
    }

    [Fact]
    public void An_application_bundle_lists_each_module_and_names_a_damaged_profile()
    {
        var bad = Zip(("module.json", "{ not json"u8.ToArray()));
        var app = Zip(("pack.info", "{}"u8.ToArray()), ("entry-default.hap", StageModule([1])), ("feature.hsp", bad));
        var found = new List<string>();
        var p = new HarmonyPackage(new MemoryStream(app), 1 << 20, (path, _) => found.Add(path));
        Assert.Equal("entry-default.hap", Assert.Single(p.Modules).Path);
        Assert.Equal(["entry-default.hap!/ets/modules.abc"], found);
        Assert.StartsWith("feature.hsp!/module.json: not readable JSON:", Assert.Single(p.Issues));
    }

    [Fact]
    public void The_harmony_view_summarizes_a_module()
    {
        using var dir = new TempDir();
        var path = dir.File("entry.hap");
        File.WriteAllBytes(path, StageModule(ArkFixtures.Features));
        var view = new HarmonyFileView().Inspect(FileInput.Open(path), default)!;
        var facts = Assert.IsType<HarmonyFacts>(view.Detail);
        Assert.Equal("com.example.ledger", Assert.Single(facts.Modules).Bundle);
        var abc = Assert.Single(facts.Bytecode);
        Assert.True(abc.ChecksumMatches);
        Assert.True(abc.Classes > 0 && abc.Methods > 0 && abc.CodeBytes > 0);
        Assert.StartsWith("HarmonyOS entry entry of com.example.ledger 1.0.2, stage model, API 12-14: 3 abilities (1 exported), 2 permissions, 1 native libraries.", view.Highlights[0]);
    }
}
