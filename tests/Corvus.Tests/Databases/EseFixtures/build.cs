#:package ManagedEsent@2.0.0
// Builds the ESE fixtures with the system esent.dll, one database per page size (8 KiB and 32 KiB):
//   ledger-8k.edb, ledger-32k.edb   gzip-compressed (.gz); table accounts: 200 rows of fixed (Id, Balance, Opened: null on every 7th row,
//                                   Active), variable (Name), tagged multi-valued (Tags: 1, 2 or 3 values), long-value
//                                   (Statement, 12,000 bytes on every 50th row, 200,000 on row 150) and compressed
//                                   (Memo: 68 characters, 4,000 on every 25th row, 30,000 on every 100th) columns, then
//                                   20 rows updated and 10 deleted;
//                                   table journal: 300 rows
// Each database is shut down clean. A computer name in either header copy is replaced and the header checksum
// recomputed; a machine or user name left anywhere in the file stops the build.
// Usage, from this folder on Windows: dotnet run build.cs
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Microsoft.Isam.Esent.Interop;
using Microsoft.Isam.Esent.Interop.Windows7;

foreach (int pageSize in new[] { 8192, 32768 })
{
    string name = $"ledger-{pageSize / 1024}k.edb";
    string work = Directory.CreateTempSubdirectory("ese-").FullName;
    string path = Path.Combine(work, name);
    SystemParameters.DatabasePageSize = pageSize;
    using (var instance = new Instance($"fixture{pageSize}"))
    {
        instance.Parameters.CircularLog = true;
        instance.Parameters.LogFileDirectory = work;
        instance.Parameters.SystemDirectory = work;
        instance.Parameters.TempDirectory = work + Path.DirectorySeparatorChar;
        instance.Parameters.NoInformationEvent = true;
        instance.Init();
        using var session = new Session(instance);
        Api.JetCreateDatabase(session, path, null, out var dbid, CreateDatabaseGrbit.OverwriteExisting);
        Api.JetBeginTransaction(session);
        Api.JetCreateTable(session, dbid, "accounts", 0, 100, out var accounts);
        JET_COLUMNID Add(JET_TABLEID t, string column, JET_coltyp type, ColumndefGrbit grbit = ColumndefGrbit.None, JET_CP cp = JET_CP.None)
        {
            Api.JetAddColumn(session, t, column, new JET_COLUMNDEF { coltyp = type, grbit = grbit, cp = cp }, null, 0, out var id);
            return id;
        }
        var id = Add(accounts, "Id", JET_coltyp.Long, ColumndefGrbit.ColumnAutoincrement | ColumndefGrbit.ColumnNotNULL);
        var balance = Add(accounts, "Balance", JET_coltyp.Currency);
        var opened = Add(accounts, "Opened", JET_coltyp.DateTime);
        var active = Add(accounts, "Active", JET_coltyp.Bit);
        var holder = Add(accounts, "Name", JET_coltyp.Text, cp: JET_CP.Unicode);
        var tags = Add(accounts, "Tags", JET_coltyp.Text, ColumndefGrbit.ColumnTagged | ColumndefGrbit.ColumnMultiValued, JET_CP.ASCII);
        var statement = Add(accounts, "Statement", JET_coltyp.LongBinary);
        var memo = Add(accounts, "Memo", JET_coltyp.LongText, Windows7Grbits.ColumnCompressed, JET_CP.Unicode);
        Api.JetCreateIndex(session, accounts, "primary", CreateIndexGrbit.IndexPrimary, "+Id\0\0", 5, 100);
        Api.JetCreateIndex(session, accounts, "by_name", CreateIndexGrbit.None, "+Name\0\0", 7, 100);
        Api.JetCreateTable(session, dbid, "journal", 0, 100, out var journal);
        var entry = Add(journal, "Entry", JET_coltyp.Long, ColumndefGrbit.ColumnAutoincrement | ColumndefGrbit.ColumnNotNULL);
        var text = Add(journal, "Text", JET_coltyp.LongText, cp: JET_CP.Unicode);
        Api.JetCreateIndex(session, journal, "primary", CreateIndexGrbit.IndexPrimary, "+Entry\0\0", 8, 100);
        Api.JetCommitTransaction(session, CommitTransactionGrbit.None);

        var epoch = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Api.JetBeginTransaction(session);
        for (int i = 1; i <= 200; i++)
        {
            using var update = new Update(session, accounts, JET_prep.Insert);
            Api.SetColumn(session, accounts, balance, (long)(i * 37 % 1000) * 10000 + i % 100 * 100);
            if (i % 7 != 0) Api.SetColumn(session, accounts, opened, epoch.AddDays(i));
            Api.SetColumn(session, accounts, active, i % 3 != 0);
            Api.SetColumn(session, accounts, holder, $"holder{i}", Encoding.Unicode);
            foreach (var tag in i % 10 == 0 ? new[] { "retail", $"region-{i % 5}", "audited" } : i % 2 == 0 ? ["retail", $"region-{i % 5}"] : [$"region-{i % 5}"])
                Api.JetSetColumn(session, accounts, tags, Encoding.ASCII.GetBytes(tag), tag.Length, SetColumnGrbit.None, new JET_SETINFO { itagSequence = 0 });
            if (i % 50 == 0)
                Api.SetColumn(session, accounts, statement, Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 14000).Select(n => $"line {n:D5}: ok\n")))[..(i == 150 ? 200000 : 12000)]);
            Api.SetColumn(session, accounts, memo, i % 25 == 0 ? string.Concat(Enumerable.Repeat($"memo for holder{i}; ", 4000))[..(i % 100 == 0 ? 30000 : 4000)] : $"memo {i}: balance reviewed, statement sent, account in good standing", Encoding.Unicode);
            update.Save();
        }
        for (int i = 1; i <= 300; i++)
        {
            using var update = new Update(session, journal, JET_prep.Insert);
            Api.SetColumn(session, journal, text, $"transfer {i * 13 % 500}.00 from holder{i % 200 + 1}", Encoding.Unicode);
            update.Save();
        }
        Api.JetCommitTransaction(session, CommitTransactionGrbit.None);

        Api.JetBeginTransaction(session);
        Api.JetSetCurrentIndex(session, accounts, "primary");
        for (int i = 1; i <= 200; i++)
        {
            if (i > 20 && i < 191) continue;
            Api.MakeKey(session, accounts, i, MakeKeyGrbit.NewKey);
            Api.JetSeek(session, accounts, SeekGrbit.SeekEQ);
            if (i > 190) { Api.JetDelete(session, accounts); continue; }
            using var update = new Update(session, accounts, JET_prep.Replace);
            Api.SetColumn(session, accounts, balance, 0L);
            Api.SetColumn(session, accounts, active, false);
            update.Save();
        }
        Api.JetCommitTransaction(session, CommitTransactionGrbit.None);
        Api.JetCloseTable(session, accounts);
        Api.JetCloseTable(session, journal);
        Api.JetCloseDatabase(session, dbid, CloseDatabaseGrbit.None);
        Api.JetDetachDatabase(session, path);
    }
    var bytes = File.ReadAllBytes(path);
    foreach (int header in new[] { 0, pageSize })
        Neutral(bytes.AsSpan(header, pageSize));
    foreach (var form in new[] { Encoding.ASCII, Encoding.Unicode })
        if (bytes.AsSpan().IndexOf(form.GetBytes(Environment.MachineName)) >= 0 || bytes.AsSpan().IndexOf(form.GetBytes(Environment.UserName)) >= 0)
            throw new InvalidDataException($"{name}: the machine or user name is still in the file");
    using (var z = new GZipStream(File.Create(Path.Combine(Directory.GetCurrentDirectory(), name + ".gz")), CompressionLevel.SmallestSize))
        z.Write(bytes);
    Directory.Delete(work, recursive: true);
    Console.WriteLine($"{name}: {bytes.Length:N0} bytes");
}

// The header signature's computer name (16 bytes at 0x10 of each signature) becomes "FIXTURE"; the checksum is the XOR
// of the header's 32-bit words from offset 4 to 668 (the header record), seeded with 0x89ABCDEF.
static void Neutral(Span<byte> header)
{
    uint stored = BinaryPrimitives.ReadUInt32LittleEndian(header);
    if (Checksum(header) != stored) throw new InvalidDataException($"header checksum 0x{stored:X8} is not the XOR rule's 0x{Checksum(header):X8}");
    var machine = Encoding.ASCII.GetBytes(Environment.MachineName);
    int replaced = 0;
    for (int at = header.IndexOf(machine); at >= 0; at = header.IndexOf(machine))
    {
        header.Slice(at, 16).Clear();
        "FIXTURE"u8.CopyTo(header[at..]);
        replaced++;
    }
    if (replaced > 0) BinaryPrimitives.WriteUInt32LittleEndian(header, Checksum(header));
}

static uint Checksum(ReadOnlySpan<byte> header)
{
    uint x = 0x89ABCDEF;
    for (int i = 4; i < 668; i += 4) x ^= BinaryPrimitives.ReadUInt32LittleEndian(header[i..]);
    return x;
}
