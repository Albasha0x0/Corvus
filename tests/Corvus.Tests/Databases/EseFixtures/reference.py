# Prints the tables and records of an ESE database as libesedb (pyesedb) reads them:
#   T <table> <columns, comma-separated> <record count>
#   R <table> <record>   a record is one field per column, joined by 0x1F (backslash, CR, LF, tab and 0x1F escaped):
#                        hex of the stored bytes, lv:<hex> for a long value, mv:<hex>,<hex> for a multi-value,
#                        s:<text> for a text column, err:<message> when pyesedb cannot read the value
# pyesedb returns multi-value fields undivided; they are split here: two-value fields (tagged flags 0x18) at their first
# byte, the size of the first value, other multi-value fields (0x08) at their offset array.
# Usage: python3 reference.py <file.edb>
import sys
import pyesedb

TEXT = (10, 12)


def escape(s):
    return s.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t").replace("\x1f", "\\x1f")


def field(record, i, ctype):
    try:
        flags = record.get_value_data_flags(i)
        if record.is_long_value(i):
            return "lv:" + (record.get_value_data_as_long_value(i).data or b"").hex()
        data = record.get_value_data(i)
        if data is None:
            return ""
        if flags & 0x10:
            first = data[0]
            return "mv:" + data[1:1 + first].hex() + "," + data[1 + first:].hex()
        if flags & 0x08:
            ends = [int.from_bytes(data[k:k + 2], "little") & 0x7FFF for k in range(0, data[0] | (data[1] & 0x7F) << 8, 2)] + [len(data)]
            return "mv:" + ",".join(data[ends[k]:ends[k + 1]].hex() for k in range(len(ends) - 1))
        if ctype in TEXT:
            return "s:" + escape(record.get_value_data_as_string(i) or "")
        return data.hex()
    except Exception as e:
        return "err:" + str(e).splitlines()[0]


def main(path):
    db = pyesedb.file()
    db.open(path)
    for t in range(db.number_of_tables):
        table = db.get_table(t)
        columns = [table.get_column(c) for c in range(table.number_of_columns)]
        print("T\t%s\t%s\t%d" % (table.name, ",".join(c.name for c in columns), table.number_of_records))
        for r in range(table.number_of_records):
            record = table.get_record(r)
            print("R\t%s\t%s" % (table.name, "\x1f".join(field(record, i, columns[i].type) for i in range(len(columns)))))
    db.close()


main(sys.argv[1])
