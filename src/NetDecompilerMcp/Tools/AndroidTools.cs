using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Services.Mobile;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

[McpServerToolType]
public sealed class AndroidTools(AndroidPackageService packages)
{
    public const string PackageDescription = "An Android package: .apk, .aab (its base module), or a split set (.apks, .xapk, .apkm, read through its base APK).";

    [McpServerTool(Name = "get_android_manifest", Title = "Android manifest", UseStructuredContent = true)]
    [Description("AndroidManifest.xml of an Android package, decoded natively (no Java tools): package, versions, min / target / compile SDK; " +
                 "permissions (also -sdk-23 and maxSdkVersion) and declared permissions with protection levels; application flags (debuggable, " +
                 "allowBackup, usesCleartextTraffic, networkSecurityConfig with its file, extractNativeLibs); every activity, alias, service, receiver " +
                 "and provider with its explicit and effective exported state and why, permissions, intent filters, launcher, deep links and " +
                 "meta-data; queries, features, libraries; highlights. Resource references are resolved. The XML itself: get_android_resource name=AndroidManifest.xml.")]
    public Task<AndroidManifestSummary> GetAndroidManifest(
        [Description(PackageDescription)] string path,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Manifest(path), cancellationToken);

    [McpServerTool(Name = "list_android_resources", Title = "List Android resources", UseStructuredContent = true)]
    [Description("Compiled resources of an Android package (resources.arsc, or resources.pb of an app bundle): one row per resource and " +
                 "configuration with id (0x7f...), type, name, configuration qualifiers (pt-rBR, b+zh+Hans, night, xxhdpi, v31; '' is the default), " +
                 "value type and value (strings, references by name, colors, dimensions, file paths; styles, arrays and plurals as name=value lists). " +
                 "types gives every resource type with its count.")]
    public Task<AndroidResourceList> ListAndroidResources(
        [Description(PackageDescription)] string path,
        [Description("Only this type: string, layout, xml, drawable, color, ...")] string? type = null,
        [Description("Only names matching this (case-insensitive; * and ? wildcards).")] string? name = null,
        [Description("Only this configuration: qualifiers as in a directory name (values-pt-rBR: pt-rBR), or default.")] string? config = null,
        [Description("Rows to skip.")] int offset = 0,
        [Description("Most rows to return (default 500).")] int limit = 500,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Resources(path, type, name, config, offset, limit), cancellationToken);

    [McpServerTool(Name = "get_android_resource", Title = "Get Android resource")]
    [Description("One file of an Android package, or one resource: a path (res/xml/network_security_config.xml, res/layout/main.xml, assets/..., " +
                 "AndroidManifest.xml) is read with binary XML decoded and resource references named, text as text, other data as a hex preview; " +
                 "@type/name or 0x7f... gives the resource's value in every configuration, or its file. savePath writes the raw bytes.")]
    public Task<string> GetAndroidResource(
        [Description(PackageDescription)] string path,
        [Description("An entry path, @type/name (@xml/network_security_config, @string/app_name) or a resource id 0x7f...")] string name,
        [Description("Write the entry's bytes to this file.")] string? savePath = null,
        [Description("Replace savePath if it exists.")] bool overwrite = false,
        [Description(OffsetDescription)] int offset = 0,
        [Description(MaxCharsDescription)] int? maxChars = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => packages.Resource(path, name, savePath, overwrite, offset, maxChars), cancellationToken);
}
