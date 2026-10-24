# Showcase: what NLog's attributes declare

The question: how does an NLog configuration name such as `File` reach its class, and where may the attributes that
carry those names be placed? The assembly is `NLog.dll` from the public NuGet package
[NLog](https://www.nuget.org/packages/NLog/6.1.4), read from the NuGet packages folder after a restore.

Read the attributes of the target class, of the attribute class that names it, and of an annotation attribute whose
`AttributeUsage` combines several targets:

<!-- check: batch show=2,3,4 -->
```json
{"tool": "load_assembly", "args": {"path": "~/.nuget/packages/nlog/6.1.4/lib/netstandard2.0/NLog.dll"}}
{"tool": "get_attributes", "args": {"assembly": "NLog", "symbol": "NLog.Targets.FileTarget"}}
{"tool": "get_attributes", "args": {"assembly": "NLog", "symbol": "NLog.Targets.TargetAttribute"}}
{"tool": "get_attributes", "args": {"assembly": "NLog", "symbol": "JetBrains.Annotations.MeansImplicitUseAttribute"}}
```

<!-- check: output -->
```text
=== [2/4] get_attributes
3 attributes (showing 1-3):
  NLog.Targets.FileTarget  [NLog]  [NullableContext(1)]
  NLog.Targets.FileTarget  [NLog]  [Nullable(0)]
  NLog.Targets.FileTarget  [NLog]  [Target("File")]
[End: 3 attributes]
=== [3/4] get_attributes
1 attribute (showing 1-1):
  NLog.Targets.TargetAttribute  [NLog]  [AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
[End: 1 attribute]
=== [4/4] get_attributes
1 attribute (showing 1-1):
  JetBrains.Annotations.MeansImplicitUseAttribute  [NLog]  [AttributeUsage(AttributeTargets.Class | AttributeTargets.Parameter | AttributeTargets.GenericParameter)]
[End: 1 attribute]
```

Every argument is decoded from the custom-attribute blob without running code: strings, the named `AllowMultiple`,
and enums by member name. A `[Flags]` value is split into its members
(`AttributeTargets.Class | AttributeTargets.GenericParameter | AttributeTargets.Parameter`), not shown as a bare 18436.
The structured result carries each argument as `{type, value, name}` for filtering. A blob that cannot be decoded is
shown as bytes, not dropped.
