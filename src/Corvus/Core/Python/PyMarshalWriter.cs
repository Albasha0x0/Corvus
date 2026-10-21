using System.Numerics;
using System.Text;

namespace Corvus.Core.Python;

/// <summary>
/// Writes objects read by <see cref="PyMarshal"/> back in the marshal format of one Python version, without back
/// references: used to save one code object of a dump whose objects share references (py2exe's script list) as its own .pyc.
/// </summary>
public static class PyMarshalWriter
{
    public static byte[] Write(object o, (int Major, int Minor) version)
    {
        using var ms = new MemoryStream();
        Write(new BinaryWriter(ms), o, version, 0);
        return ms.ToArray();
    }

    private static void Write(BinaryWriter w, object o, (int Major, int Minor) v, int depth)
    {
        if (depth > 400) throw new ToolError(ErrorCode.MalformedInput, "marshal data: nesting too deep to write.");
        switch (o)
        {
            case PySingleton s:
                w.Write((byte)(s == PySingleton.None ? 'N' : s == PySingleton.Ellipsis ? '.' : 'S'));
                break;
            case bool b:
                w.Write((byte)(b ? 'T' : 'F'));
                break;
            case long l when l is >= int.MinValue and <= int.MaxValue:
                w.Write((byte)'i');
                w.Write((int)l);
                break;
            case long l:
                Long(w, l);
                break;
            case BigInteger big:
                Long(w, big);
                break;
            case double d:
                w.Write((byte)'g');
                w.Write(d);
                break;
            case PyComplex c:
                w.Write((byte)'y');
                w.Write(c.Real);
                w.Write(c.Imaginary);
                break;
            case PyBytes bytes:
                w.Write((byte)'s');
                w.Write(bytes.Value.Length);
                w.Write(bytes.Value);
                break;
            case string s when v.Major == 2:
                var latin = Encoding.Latin1.GetBytes(s);
                w.Write((byte)'t');
                w.Write(latin.Length);
                w.Write(latin);
                break;
            case string s:
                var utf8 = Encoding.UTF8.GetBytes(s);
                w.Write((byte)'u');
                w.Write(utf8.Length);
                w.Write(utf8);
                break;
            case PySequence seq:
                w.Write((byte)seq.Kind);
                w.Write(seq.Items.Length);
                foreach (var item in seq.Items) Write(w, item, v, depth + 1);
                break;
            case PyDict dict:
                w.Write((byte)'{');
                foreach (var kv in dict.Items)
                {
                    Write(w, kv.Key, v, depth + 1);
                    Write(w, kv.Value, v, depth + 1);
                }
                w.Write((byte)'0');
                break;
            case PySlice slice:
                w.Write((byte)':');
                Write(w, slice.Start, v, depth + 1);
                Write(w, slice.Stop, v, depth + 1);
                Write(w, slice.Step, v, depth + 1);
                break;
            case PyCode c:
                Code(w, c, v, depth);
                break;
            default:
                throw new ToolError(ErrorCode.MalformedInput, $"marshal data: cannot write a {o.GetType().Name}.");
        }
    }

    private static void Long(BinaryWriter w, BigInteger value)
    {
        var digits = new List<ushort>();
        for (var m = BigInteger.Abs(value); m > 0; m >>= 15) digits.Add((ushort)(m & 0x7FFF));
        w.Write((byte)'l');
        w.Write(value.Sign < 0 ? -digits.Count : digits.Count);
        foreach (var d in digits) w.Write(d);
    }

    private static void Code(BinaryWriter w, PyCode c, (int Major, int Minor) v, int depth)
    {
        static PySequence Of(object[] items) => new('(', items);
        w.Write((byte)'c');
        w.Write(c.ArgCount);
        if (PyVersion.AtLeast(v, 3, 8)) w.Write(c.PosOnlyArgCount);
        if (v.Major >= 3) w.Write(c.KwOnlyArgCount);
        if (!PyVersion.AtLeast(v, 3, 11)) w.Write(c.NLocals);
        w.Write(c.StackSize);
        w.Write(c.Flags);
        Write(w, new PyBytes(c.Code), v, depth + 1);
        Write(w, Of(c.Consts), v, depth + 1);
        Write(w, Of(c.Names), v, depth + 1);
        if (PyVersion.AtLeast(v, 3, 11))
        {
            Write(w, Of(c.LocalsPlusNames), v, depth + 1);
            Write(w, new PyBytes(c.LocalsPlusKinds), v, depth + 1);
        }
        else
        {
            Write(w, Of(c.VarNames), v, depth + 1);
            Write(w, Of(c.FreeVars), v, depth + 1);
            Write(w, Of(c.CellVars), v, depth + 1);
        }
        Write(w, c.Filename, v, depth + 1);
        Write(w, c.Name, v, depth + 1);
        if (PyVersion.AtLeast(v, 3, 11)) Write(w, c.QualName, v, depth + 1);
        w.Write(c.FirstLineNo);
        Write(w, new PyBytes(c.LineTable), v, depth + 1);
        if (PyVersion.AtLeast(v, 3, 11)) Write(w, new PyBytes(c.ExceptionTable), v, depth + 1);
    }
}
