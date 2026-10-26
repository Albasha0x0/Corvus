// Builds ledger.realm with the realm package 12.14.2 (Realm Core 14, file format 24):
//   Holder   name (primary key), since (date)
//   Account  id (primary key, int), owner (link to Holder), balance (double), opened (date, optional), active (bool),
//            tags (list of strings), note (optional string; 4,000 characters on every 25th), photo (optional data),
//            code (uuid), ref (objectId), total (decimal128)
//   Journal  entry (int), text (string), amount (float)
// 200 accounts and 300 journal entries are written in one transaction; a second overwrites accounts 1 to 20 and
// deletes 191 to 200. The file is written to the folder given, or this one.
// Usage: node build.js [folder] (needs the realm package; NODE_PATH names the folder holding it).
const path = require("path");
const fs = require("fs");
const Realm = require("realm");

const out = path.join(process.argv[2] || __dirname, "ledger.realm");
for (const suffix of ["", ".lock", ".note", ".management"]) fs.rmSync(out + suffix, { recursive: true, force: true });

const Holder = { name: "Holder", primaryKey: "name", properties: { name: "string", since: "date" } };
const Account = {
  name: "Account",
  primaryKey: "id",
  properties: {
    id: "int", owner: "Holder?", balance: "double", opened: "date?", active: "bool", tags: "string[]", note: "string?",
    photo: "data?", code: "uuid", ref: "objectId", total: "decimal128",
  },
};
const Journal = { name: "Journal", properties: { entry: "int", text: "string", amount: "float" } };

const realm = new Realm({ path: out, schema: [Holder, Account, Journal], schemaVersion: 1 });
const epoch = Date.UTC(2026, 0, 1);
const hex = (n, width) => n.toString(16).padStart(width, "0");
realm.write(() => {
  const holders = [];
  for (let i = 1; i <= 50; i++) holders.push(realm.create("Holder", { name: `holder${i}`, since: new Date(epoch + i * 86400000) }));
  for (let i = 1; i <= 200; i++) {
    realm.create("Account", {
      id: i,
      owner: holders[i % 50],
      balance: (i * 37 % 1000) + (i % 100) / 100,
      opened: i % 7 === 0 ? null : new Date(epoch + i * 86400000),
      active: i % 3 !== 0,
      tags: i % 10 === 0 ? ["retail", `region-${i % 5}`, "audited"] : i % 2 === 0 ? ["retail", `region-${i % 5}`] : [`region-${i % 5}`],
      note: i % 25 === 0 ? `note for account ${i}; `.repeat(300).slice(0, 4000) : i % 4 === 0 ? null : `note ${i}`,
      photo: i % 50 === 0 ? new Uint8Array(Array.from({ length: 3000 }, (_, k) => (k * 7 + i) % 256)).buffer : null,
      code: new Realm.BSON.UUID(`${hex(i, 8)}-0000-4000-8000-${hex(i * 31, 12)}`),
      ref: new Realm.BSON.ObjectId(hex(i, 24)),
      total: Realm.BSON.Decimal128.fromString(`${i}.25`),
    });
  }
  for (let i = 1; i <= 300; i++) realm.create("Journal", { entry: i, text: `transfer ${i * 13 % 500}.00 from holder${i % 50 + 1}`, amount: i / 4 });
});
realm.write(() => {
  for (let i = 1; i <= 20; i++) {
    const a = realm.objectForPrimaryKey("Account", i);
    a.balance = 0;
    a.active = false;
  }
  for (let i = 191; i <= 200; i++) realm.delete(realm.objectForPrimaryKey("Account", i));
});
realm.close();
for (const suffix of [".lock", ".note", ".management"]) fs.rmSync(out + suffix, { recursive: true, force: true });
console.log(`${path.basename(out)}: ${fs.statSync(out).size} bytes`);
// The realm package keeps the event loop alive after close.
process.exit(0);
