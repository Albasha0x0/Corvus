// Prints what the realm package reads from a Realm file, for RealmTests to compare:
//   T <class> <objects>
//   R <class> <key> <property>=<value> ... (properties sorted by name)
// Values: null, integers and booleans as text, s:<utf-8 hex>, b:<hex>, f:<IEEE double bits hex> (floats widened),
// d:<milliseconds>, u:<uuid hex>, o:<objectId hex>, m:<decimal128 text>, k:<class>#<key> for links, [a,b] for lists
// and sets, {key=value} for dictionaries (keys sorted). Embedded classes are listed by T only.
// Usage: node reference.js <file> (NODE_PATH names the folder holding the realm package).
const Realm = require("realm");

const realm = new Realm({ path: process.argv[2], readOnly: true });
const bits = new DataView(new ArrayBuffer(8));
const hex = (bytes) => Buffer.from(bytes).toString("hex");

function value(v, type) {
  if (v === null || v === undefined) return "null";
  switch (type) {
    case "int": return String(v);
    case "bool": return v ? "true" : "false";
    case "string": return "s:" + Buffer.from(v, "utf8").toString("hex");
    case "data": return "b:" + hex(new Uint8Array(v));
    case "float":
    case "double": bits.setFloat64(0, v); return "f:" + bits.getBigUint64(0).toString(16);
    case "date": return "d:" + v.getTime();
    case "uuid": return "u:" + v.toHexString().replace(/-/g, "");
    case "objectId": return "o:" + v.toHexString();
    case "decimal128": return "m:" + v.toString();
    case "object":
    case "linkingObjects": return "k:" + v.objectSchema().name + "#" + v._objectKey();
    case "mixed": return mixed(v);
    // Collections of objects name the class as their element type.
    default: return v instanceof Realm.Object ? value(v, "object") : "?" + type;
  }
}

function mixed(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return value(v, "bool");
  if (typeof v === "string") return value(v, "string");
  // JavaScript reads integers and doubles in a mixed value as one number type.
  if (typeof v === "number") return value(v, "double");
  if (typeof v === "bigint") return String(v);
  if (v instanceof Date) return value(v, "date");
  if (v instanceof ArrayBuffer) return value(v, "data");
  if (v instanceof Realm.BSON.UUID) return value(v, "uuid");
  if (v instanceof Realm.BSON.ObjectId) return value(v, "objectId");
  if (v instanceof Realm.BSON.Decimal128) return value(v, "decimal128");
  if (v instanceof Realm.Object) return value(v, "object");
  return "?mixed";
}

function property(v, p) {
  if (p.type === "list" || p.type === "set") return "[" + [...v].map((e) => value(e, p.objectType)).join(",") + "]";
  if (p.type === "dictionary") {
    return "{" + Object.keys(v).sort().map((k) => k + "=" + value(v[k], p.objectType)).join(",") + "}";
  }
  return value(v, p.type);
}

for (const schema of [...realm.schema].sort((a, b) => a.name.localeCompare(b.name))) {
  if (schema.embedded) {
    console.log(`T\t${schema.name}\tembedded`);
    continue;
  }
  const objects = realm.objects(schema.name);
  console.log(`T\t${schema.name}\t${objects.length}`);
  const props = Object.entries(schema.properties).filter(([, p]) => p.type !== "linkingObjects").sort(([a], [b]) => (a < b ? -1 : 1));
  for (const o of objects) {
    console.log(`R\t${schema.name}\t${o._objectKey()}\t` + props.map(([name, p]) => name + "=" + property(o[name], p)).join("\t"));
  }
}
realm.close();
// The realm package keeps the event loop alive after close.
process.exit(0);
