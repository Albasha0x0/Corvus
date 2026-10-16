using System.Text;

namespace Corvus.Core.Mobile;

/// <summary>A Java type in a descriptor or a generic Signature attribute (JVMS 4.7.9.1).</summary>
public abstract record JvmType;
public sealed record JvmBaseType(char Code) : JvmType;
public sealed record JvmClassType(JvmClassType? Outer, string Name, IReadOnlyList<JvmTypeArgument> Arguments) : JvmType;
public sealed record JvmTypeVariable(string Name) : JvmType;
public sealed record JvmArrayType(JvmType Component) : JvmType;

/// <summary>A type argument: '*' unbounded, '+' extends, '-' super, '=' exact.</summary>
public sealed record JvmTypeArgument(char Wildcard, JvmType? Bound);
public sealed record JvmTypeParameter(string Name, JvmType? ClassBound, IReadOnlyList<JvmType> InterfaceBounds);
public sealed record JvmClassSignature(IReadOnlyList<JvmTypeParameter> Parameters, JvmClassType? Superclass, IReadOnlyList<JvmClassType> Interfaces);
public sealed record JvmMethodSignature(IReadOnlyList<JvmTypeParameter> Parameters, IReadOnlyList<JvmType> Arguments, JvmType Result, IReadOnlyList<JvmType> Throws);

/// <summary>Parses descriptors and generic signatures, and prints them as Java source types (javap's form).</summary>
public static class JvmSignatures
{
    public static JvmType Field(string text)
    {
        var p = new Parser(text);
        var t = p.Type();
        p.End();
        return t;
    }

    public static JvmMethodSignature Method(string text)
    {
        var p = new Parser(text);
        var parameters = p.TypeParameters();
        p.Expect('(');
        var args = new List<JvmType>();
        while (p.Peek != ')') args.Add(p.Type());
        p.Expect(')');
        var result = p.Peek == 'V' ? p.Base() : p.Type();
        var throws = new List<JvmType>();
        while (p.Peek == '^')
        {
            p.Expect('^');
            throws.Add(p.Type());
        }
        p.End();
        return new JvmMethodSignature(parameters, args, result, throws);
    }

    public static JvmClassSignature Class(string text)
    {
        var p = new Parser(text);
        var parameters = p.TypeParameters();
        var super = p.ClassType();
        var interfaces = new List<JvmClassType>();
        while (p.Peek == 'L') interfaces.Add(p.ClassType());
        p.End();
        return new JvmClassSignature(parameters, super, interfaces);
    }

    public static bool IsObject(JvmType? t) => t is JvmClassType { Outer: null, Name: "java/lang/Object", Arguments.Count: 0 };

    public static string BaseName(char code) => code switch
    {
        'B' => "byte", 'C' => "char", 'D' => "double", 'F' => "float", 'I' => "int", 'J' => "long", 'S' => "short", 'Z' => "boolean", 'V' => "void",
        _ => throw new InvalidDataException($"unknown base type {code}"),
    };

    public static string Print(JvmType t)
    {
        var sb = new StringBuilder();
        Print(sb, t);
        return sb.ToString();
    }

    public static void Print(StringBuilder sb, JvmType t)
    {
        switch (t)
        {
            case JvmBaseType b: sb.Append(BaseName(b.Code)); break;
            case JvmClassType c:
                if (c.Outer != null)
                {
                    Print(sb, c.Outer);
                    sb.Append('.');
                }
                sb.Append(c.Name.Replace('/', '.'));
                if (c.Arguments.Count > 0)
                {
                    sb.Append('<');
                    for (int i = 0; i < c.Arguments.Count; i++)
                    {
                        if (i > 0) sb.Append(", ");
                        var a = c.Arguments[i];
                        if (a.Wildcard == '*') sb.Append('?');
                        else
                        {
                            sb.Append(a.Wildcard switch { '+' => "? extends ", '-' => "? super ", _ => "" });
                            Print(sb, a.Bound!);
                        }
                    }
                    sb.Append('>');
                }
                break;
            case JvmTypeVariable v: sb.Append(v.Name); break;
            case JvmArrayType a:
                Print(sb, a.Component);
                sb.Append("[]");
                break;
        }
    }

    /// <summary>Type parameters with bounds, an Object class bound left out.</summary>
    public static string Print(IReadOnlyList<JvmTypeParameter> parameters)
    {
        if (parameters.Count == 0) return "";
        var sb = new StringBuilder("<");
        for (int i = 0; i < parameters.Count; i++)
        {
            var tp = parameters[i];
            if (i > 0) sb.Append(", ");
            sb.Append(tp.Name);
            var sep = " extends ";
            if (tp.ClassBound != null && !IsObject(tp.ClassBound))
            {
                sb.Append(sep);
                Print(sb, tp.ClassBound);
                sep = " & ";
            }
            foreach (var bound in tp.InterfaceBounds)
            {
                sb.Append(sep);
                Print(sb, bound);
                sep = " & ";
            }
        }
        return sb.Append('>').ToString();
    }

    private sealed class Parser(string s)
    {
        private int _i;

        public char Peek => _i < s.Length ? s[_i] : '\0';

        public void Expect(char c)
        {
            if (Peek != c) throw new InvalidDataException($"signature '{s}': expected '{c}' at {_i}");
            _i++;
        }

        public void End()
        {
            if (_i != s.Length) throw new InvalidDataException($"signature '{s}': unexpected text at {_i}");
        }

        public JvmBaseType Base() => new(s[_i++]);

        public JvmType Type() => Peek switch
        {
            'B' or 'C' or 'D' or 'F' or 'I' or 'J' or 'S' or 'Z' => Base(),
            'L' => ClassType(),
            'T' => Variable(),
            '[' => Array(),
            _ => throw new InvalidDataException($"signature '{s}': unexpected '{Peek}' at {_i}"),
        };

        private JvmArrayType Array()
        {
            Expect('[');
            return new JvmArrayType(Type());
        }

        private JvmTypeVariable Variable()
        {
            Expect('T');
            var name = Identifier();
            Expect(';');
            return new JvmTypeVariable(name);
        }

        public JvmClassType ClassType()
        {
            Expect('L');
            var type = new JvmClassType(null, Identifier(slash: true), Arguments());
            while (Peek == '.')
            {
                _i++;
                type = new JvmClassType(type, Identifier(), Arguments());
            }
            Expect(';');
            return type;
        }

        private List<JvmTypeArgument> Arguments()
        {
            var list = new List<JvmTypeArgument>();
            if (Peek != '<') return list;
            _i++;
            while (Peek != '>')
            {
                if (Peek == '*') { _i++; list.Add(new JvmTypeArgument('*', null)); }
                else if (Peek is '+' or '-') { var w = s[_i++]; list.Add(new JvmTypeArgument(w, Type())); }
                else list.Add(new JvmTypeArgument('=', Type()));
            }
            if (list.Count == 0) throw new InvalidDataException($"signature '{s}': empty type arguments at {_i}");
            _i++;
            return list;
        }

        public List<JvmTypeParameter> TypeParameters()
        {
            var list = new List<JvmTypeParameter>();
            if (Peek != '<') return list;
            _i++;
            while (Peek != '>')
            {
                var name = Identifier(colon: true);
                Expect(':');
                JvmType? classBound = Peek is 'L' or 'T' or '[' ? Type() : null;
                var interfaces = new List<JvmType>();
                while (Peek == ':')
                {
                    _i++;
                    interfaces.Add(Type());
                }
                list.Add(new JvmTypeParameter(name, classBound, interfaces));
            }
            if (list.Count == 0) throw new InvalidDataException($"signature '{s}': empty type parameters");
            _i++;
            return list;
        }

        private string Identifier(bool slash = false, bool colon = false)
        {
            int start = _i;
            while (_i < s.Length && s[_i] is not (';' or '<' or '>' or '.' or '[') && (slash || s[_i] != '/') && (!colon || s[_i] != ':')) _i++;
            if (_i == start) throw new InvalidDataException($"signature '{s}': expected a name at {_i}");
            return s[start.._i];
        }
    }
}
