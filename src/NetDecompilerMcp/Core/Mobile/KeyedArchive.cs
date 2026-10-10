using System.Globalization;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Core.Mobile;

/// <summary>
/// NSKeyedArchiver files (archived objects, nib and storyboard contents, saved state) projected from the flat
/// $objects table into an object graph. Each archived object becomes a dictionary with "$class" (and "$classes", its
/// superclass chain) and "$uid"; its fields follow with references resolved. An object met again (shared, or a cycle)
/// is written as {"$ref": uid}. Foundation collections, strings, data, dates, UUIDs and URLs become plain values.
/// </summary>
public static class KeyedArchive
{
    public sealed record Result(PlistNode Root, IReadOnlyList<ParseIssue> Issues);

    public static bool IsKeyedArchive(PlistNode? root) =>
        root is PlistDict d && d["$archiver"] is PlistString { Value: var archiver } && archiver.StartsWith("NSKeyedArchiver", StringComparison.Ordinal)
        && d["$objects"] is PlistArray && d["$top"] is PlistDict;

    /// <summary>Projects an archive; a root that is not one is returned unchanged with an issue.</summary>
    public static Result Project(PlistNode root, int maxObjects = Plist.MaxObjects)
    {
        if (!IsKeyedArchive(root)) return new(root, [new ParseIssue("keyed archive", "not an NSKeyedArchiver archive")]);
        var p = new Projector((PlistArray)((PlistDict)root)["$objects"]!, maxObjects);
        var top = (PlistDict)((PlistDict)root)["$top"]!;
        PlistNode result = top.Entries.Count == 1 && top.Entries[0].Key == "root"
            ? p.Resolve(top.Entries[0].Value, 0)
            : new PlistDict(top.Entries.Select(e => new KeyValuePair<string, PlistNode>(e.Key, p.Resolve(e.Value, 0))).ToList());
        return new(result, p.Issues);
    }

    private sealed class Projector(PlistArray objects, int maxObjects)
    {
        private const string Area = "keyed archive";
        public List<ParseIssue> Issues { get; } = [];
        private readonly HashSet<ulong> _seen = [], _inProgress = [];
        private int _count;

        public PlistNode Resolve(PlistNode node, int depth)
        {
            if (depth > Plist.MaxDepth) return Stop($"nested deeper than {Plist.MaxDepth}");
            return node switch
            {
                PlistUid uid => Object(uid.Value, depth),
                PlistArray a => new PlistArray(a.Items.Select(i => Resolve(i, depth + 1)).ToList(), a.IsSet),
                PlistDict d => new PlistDict(d.Entries.Select(e => new KeyValuePair<string, PlistNode>(e.Key, Resolve(e.Value, depth + 1))).ToList()),
                _ => node,
            };
        }

        private PlistNode Stop(string message)
        {
            if (Issues.All(i => i.Message != message)) Issues.Add(new(Area, message));
            return PlistNull.Value;
        }

        private PlistNode Object(ulong uid, int depth)
        {
            if (uid >= (ulong)objects.Items.Count)
            {
                Issues.Add(new(Area, $"reference {uid} is not one of the {objects.Items.Count} objects"));
                return PlistNull.Value;
            }
            var obj = objects.Items[(int)uid];
            if (obj is PlistString { Value: "$null" } && uid == 0) return PlistNull.Value;
            if (obj is not (PlistDict or PlistArray)) return obj;
            if (++_count > maxObjects) return Stop($"more than {maxObjects} objects");
            if (obj is not PlistDict dict || dict["$class"] is not { } classRef)
            {
                // A container stored without a class: inlined, except inside itself.
                if (!_inProgress.Add(uid)) return Ref(uid);
                var inlined = Resolve(obj, depth + 1);
                _inProgress.Remove(uid);
                return inlined;
            }
            if (!_seen.Add(uid)) return Ref(uid);
            var (name, chain) = ClassOf(classRef);
            var field = (string key) => dict[key] is { } v ? Resolve(v, depth + 1) : null;
            switch (name)
            {
                case "NSArray" or "NSMutableArray" or "NSSet" or "NSMutableSet" or "NSOrderedSet" or "NSMutableOrderedSet" when field("NS.objects") is PlistArray items:
                    return items with { IsSet = name.Contains("Set", StringComparison.Ordinal) };
                case "NSDictionary" or "NSMutableDictionary" when field("NS.keys") is PlistArray keys && field("NS.objects") is PlistArray values:
                    return new PlistDict(keys.Items.Zip(values.Items, (k, v) => new KeyValuePair<string, PlistNode>(KeyText(k), v)).ToList());
                case "NSString" or "NSMutableString" when field("NS.string") is PlistString s:
                    return s;
                case "NSData" or "NSMutableData" when field("NS.data") is PlistData data:
                    return data;
                case "NSDate" when field("NS.time") is PlistReal time && double.IsFinite(time.Value) && Math.Abs(time.Value) < 3e11:
                    return new PlistDate(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero).AddTicks((long)(time.Value * TimeSpan.TicksPerSecond)));
                case "NSUUID" when field("NS.uuidbytes") is PlistData { Value.Length: 16 } bytes:
                    return new PlistString(new Guid(bytes.Value, bigEndian: true).ToString());
                case "NSURL" when field("NS.relative") is PlistString relative:
                    return field("NS.base") is PlistString b ? new PlistString(b.Value + relative.Value) : relative;
                case "NSNull":
                    return PlistNull.Value;
            }
            var entries = new List<KeyValuePair<string, PlistNode>>
            {
                new("$class", new PlistString(name)),
                new("$uid", new PlistInteger(uid)),
            };
            if (chain.Count > 1) entries.Add(new("$classes", new PlistArray(chain.Select(c => (PlistNode)new PlistString(c)).ToList())));
            foreach (var (key, value) in dict.Entries)
                if (key != "$class") entries.Add(new(key, Resolve(value, depth + 1)));
            return new PlistDict(entries);
        }

        private static PlistDict Ref(ulong uid) => new([new("$ref", new PlistInteger(uid))]);

        private (string Name, IReadOnlyList<string> Chain) ClassOf(PlistNode classRef)
        {
            if (classRef is PlistUid u && u.Value < (ulong)objects.Items.Count && objects.Items[(int)u.Value] is PlistDict c && c["$classname"] is PlistString n)
                return (n.Value, c["$classes"] is PlistArray chain ? chain.Items.OfType<PlistString>().Select(s => s.Value).ToList() : [n.Value]);
            Issues.Add(new(Area, "an object's $class does not name a class"));
            return ("?", []);
        }

        private static string KeyText(PlistNode key) => key switch
        {
            PlistString s => s.Value,
            PlistInteger i => i.Value.ToString(CultureInfo.InvariantCulture),
            PlistDict d when d["$ref"] is PlistInteger r => $"$ref {r.Value}",
            _ => key.GetType().Name,
        };
    }
}
