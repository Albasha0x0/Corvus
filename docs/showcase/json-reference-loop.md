# Showcase: a Json.NET error traced to its code

The behaviour: serializing an object graph with a cycle fails with "Self referencing loop detected". Which code
decides that, which setting changes it, and which paths reach it? The assembly is `Newtonsoft.Json.dll` from the public
NuGet package [Newtonsoft.Json](https://www.nuget.org/packages/Newtonsoft.Json/13.0.4), read from the NuGet packages
folder after a restore.

Find the message, read the method that holds it, list its callers, then record the three findings as an evidence
bundle and check it:

<!-- check: batch show=1,2,3,4,6 -->
```json
{"tool": "load_assembly", "args": {"path": "~/.nuget/packages/newtonsoft.json/13.0.4/lib/net6.0/Newtonsoft.Json.dll"}}
{"tool": "search_strings", "args": {"assembly": "Newtonsoft.Json", "query": "Self referencing loop"}}
{"tool": "decompile_member", "args": {"assembly": "Newtonsoft.Json", "member": "0x060007AB"}}
{"tool": "find_references", "args": {"assembly": "Newtonsoft.Json", "symbol": "0x060007AB"}}
{"tool": "read_result", "args": {"id": "last:3", "format": "evidence", "outputPath": "samples/bin/json-reference-loop.json", "overwrite": true}}
{"tool": "read_result", "args": {"id": "samples/bin/json-reference-loop.json", "format": "verify"}}
```

<!-- check: output -->
```text
=== [1/6] load_assembly
Loaded Newtonsoft.Json: Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4fe6b2a6aeed
  ~/.nuget/packages/newtonsoft.json/13.0.4/lib/net6.0/Newtonsoft.Json.dll
  500 types, 12 namespaces
=== [2/6] search_strings
1 occurrence (showing 1-1):
  "Self referencing loop detected"
      in Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::CheckForCircularReference(JsonWriter, object, JsonProperty, JsonContract, JsonContainerContract, JsonProperty) @IL_008E  [Newtonsoft.Json] 0x060007AB
[End: 1 occurrence]
=== [3/6] decompile_member
// [Newtonsoft.Json]
// Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::CheckForCircularReference(JsonWriter, object, JsonProperty, JsonContract, JsonContainerContract, JsonProperty)  [token 0x060007AB]
using System.Diagnostics;
using System.Globalization;
using Newtonsoft.Json.Utilities;

private bool CheckForCircularReference(JsonWriter writer, object? value, JsonProperty? property, JsonContract? contract, JsonContainerContract? containerContract, JsonProperty? containerProperty)
{
	if (value == null)
	{
		return true;
	}
	if (contract.ContractType == JsonContractType.Primitive || contract.ContractType == JsonContractType.String)
	{
		return true;
	}
	ReferenceLoopHandling? referenceLoopHandling = null;
	if (property != null)
	{
		referenceLoopHandling = property.ReferenceLoopHandling;
	}
	if (!referenceLoopHandling.HasValue && containerProperty != null)
	{
		referenceLoopHandling = containerProperty.ItemReferenceLoopHandling;
	}
	if (!referenceLoopHandling.HasValue && containerContract != null)
	{
		referenceLoopHandling = containerContract.ItemReferenceLoopHandling;
	}
	if ((Serializer._equalityComparer != null) ? _serializeStack.Contains(value, Serializer._equalityComparer) : _serializeStack.Contains(value))
	{
		string text = "Self referencing loop detected";
		if (property != null)
		{
			text += " for property '{0}'".FormatWith(CultureInfo.InvariantCulture, property.PropertyName);
		}
		text += " with type '{0}'.".FormatWith(CultureInfo.InvariantCulture, value.GetType());
		switch (referenceLoopHandling.GetValueOrDefault(Serializer._referenceLoopHandling))
		{
		case ReferenceLoopHandling.Error:
			throw JsonSerializationException.Create(null, writer.ContainerPath, text, null);
		case ReferenceLoopHandling.Ignore:
			if (TraceWriter != null && TraceWriter.LevelFilter >= TraceLevel.Verbose)
			{
				TraceWriter.Trace(TraceLevel.Verbose, JsonPosition.FormatMessage(null, writer.Path, text + ". Skipping serializing self referenced value."), null);
			}
			return false;
		case ReferenceLoopHandling.Serialize:
			if (TraceWriter != null && TraceWriter.LevelFilter >= TraceLevel.Verbose)
			{
				TraceWriter.Trace(TraceLevel.Verbose, JsonPosition.FormatMessage(null, writer.Path, text + ". Serializing self referenced value."), null);
			}
			return true;
		}
	}
	return true;
}
=== [4/6] find_references
References to method Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::CheckForCircularReference(JsonWriter, object, JsonProperty, JsonContract, JsonContainerContract, JsonProperty) [Newtonsoft.Json]: 8 references (showing 1-8):
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeObject(JsonWriter, object, JsonObjectContract, JsonProperty, JsonContainerContract, JsonProperty)  [Newtonsoft.Json] 0x060007B2  IL_015C  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::CalculatePropertyValues(JsonWriter, object, JsonContainerContract, JsonProperty, JsonProperty, ref JsonContract, ref object)  [Newtonsoft.Json] 0x060007B3  IL_00DA  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeConvertable(JsonWriter, JsonConverter, object, JsonContract, JsonContainerContract, JsonProperty)  [Newtonsoft.Json] 0x060007BB  IL_0023  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeList(JsonWriter, IEnumerable, JsonArrayContract, JsonProperty, JsonContainerContract, JsonProperty)  [Newtonsoft.Json] 0x060007BC  IL_0098  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeMultidimensionalArray(JsonWriter, Array, JsonArrayContract, JsonProperty, int, int[])  [Newtonsoft.Json] 0x060007BE  IL_008A  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeISerializable(JsonWriter, ISerializable, JsonISerializableContract, JsonProperty, JsonContainerContract, JsonProperty)  [Newtonsoft.Json] 0x060007C0  IL_00E9  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeDynamic(JsonWriter, IDynamicMetaObjectProvider, JsonDynamicContract, JsonProperty, JsonContainerContract, JsonProperty)  [Newtonsoft.Json] 0x060007C1  IL_00F5  call
  Newtonsoft.Json.Serialization.JsonSerializerInternalWriter::SerializeDictionary(JsonWriter, IDictionary, JsonDictionaryContract, JsonProperty, JsonContainerContract, JsonProperty)  [Newtonsoft.Json] 0x060007C4  IL_0136  call
[End: 8 references]
=== [6/6] read_result
samples/bin/json-reference-loop.json: 3 record(s), 3 verified, 0 differ (each call re-run)
  ok  c-2 search_strings: same content
  ok  c-3 decompile_member: same content
  ok  c-4 find_references: same content
```

- **Decision:** the message lives in one method, `JsonSerializerInternalWriter.CheckForCircularReference`. It looks
  for the value on the stack of objects being serialized, and the effective `ReferenceLoopHandling` decides the
  outcome: the property's setting first, then the container's item setting, then the serializer's. `Error` throws,
  `Ignore` skips the value and `Serialize` writes it again.
- **Callers:** every container writer calls the check: objects, lists, arrays, dictionaries, `ISerializable`, dynamic
  objects and values written by a converter.
- **Evidence:** step 5 writes the three calls to a bundle (not shown: its size and hash change with the build). The
  bundle names the assembly each call read by its SHA-256 and keeps the SHA-256 of each result, so `format=verify`
  reports a record as differing when its input or its result has changed.
