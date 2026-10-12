using System.Text;
using K = Corvus.Native.Swift.SwiftNodeKind;

namespace Corvus.Native.Swift;

public static partial class SwiftDemangler
{
    /// <summary>The Swift 1-3 mangling ("_T"), a recursive-descent grammar; still used for ObjC runtime names of Swift classes ("_TtC").</summary>
    private sealed class OldParser(string text)
    {
        private const int MaxDepth = 1024;
        private readonly List<SwiftNode> subs = [];
        private int pos;
        private int nodes;

        private SwiftNode N(K kind)
        {
            if (++nodes > MaxNodes) throw new TooComplex();
            return new SwiftNode(kind);
        }

        private SwiftNode N(K kind, string t)
        {
            if (++nodes > MaxNodes) throw new TooComplex();
            return new SwiftNode(kind) { Text = t };
        }

        private SwiftNode N(K kind, ulong index)
        {
            if (++nodes > MaxNodes) throw new TooComplex();
            return new SwiftNode(kind) { Index = index, HasIndex = true };
        }

        private bool Empty => pos >= text.Length;
        private char Peek() => Empty ? '.' : text[pos];

        private char Next()
        {
            char c = Peek();
            if (!Empty) pos++;
            return c;
        }

        private bool NextIf(char c)
        {
            if (Empty || Peek() != c) return false;
            pos++;
            return true;
        }

        private bool NextIf(string s)
        {
            if (pos + s.Length > text.Length || string.CompareOrdinal(text, pos, s, 0, s.Length) != 0) return false;
            pos += s.Length;
            return true;
        }

        private bool ReadUntil(char c, StringBuilder result)
        {
            char? last = null;
            while (!Empty && (last = Peek()) != c)
            {
                result.Append(last.Value);
                pos++;
            }
            return last == c;
        }

        public SwiftNode? DemangleTopLevel()
        {
            if (!NextIf("_T")) return null;
            var top = N(K.Global);
            if (NextIf("TS"))
            {
                do
                {
                    if (DemangleSpecializedAttribute(0) is not { } attr) return null;
                    top.Add(attr);
                    subs.Clear();
                } while (NextIf("_TTS"));
                if (!NextIf("_T")) return null;
            }
            else if (NextIf("To")) top.Add(N(K.ObjCAttribute));
            else if (NextIf("TO")) top.Add(N(K.NonObjCAttribute));
            else if (NextIf("TD")) top.Add(N(K.DynamicAttribute));
            else if (NextIf("Td")) top.Add(N(K.DirectMethodReferenceAttribute));
            else if (NextIf("TV")) top.Add(N(K.VTableAttribute));
            if (DemangleGlobal(0) is not { } global) return null;
            top.Add(global);
            if (!Empty)
            {
                top.Add(N(K.Suffix, text[pos..]));
                pos = text.Length;
            }
            return top;
        }

        private bool DemangleNatural(out ulong num)
        {
            num = 0;
            if (Empty) return false;
            char c = Next();
            if (c is < '0' or > '9') return false;
            num = (ulong)(c - '0');
            while (true)
            {
                if (Empty) return true;
                c = Peek();
                if (c is < '0' or > '9') return true;
                num = unchecked(10 * num + (ulong)(c - '0'));
                Next();
            }
        }

        private bool DemangleBuiltinSize(out ulong num) => DemangleNatural(out num) && NextIf('_');

        private SwiftNode? Add(SwiftNode parent, SwiftNode? child)
        {
            if (child == null) return null;
            parent.Add(child);
            return parent;
        }

        private SwiftNode? DemangleGlobal(int depth)
        {
            CheckStack();
            if (depth > MaxDepth || Empty) return null;
            if (NextIf('M'))
            {
                if (NextIf('P')) return Add(N(K.GenericTypeMetadataPattern), DemangleType(depth + 1));
                if (NextIf('a')) return Add(N(K.TypeMetadataAccessFunction), DemangleType(depth + 1));
                if (NextIf('L')) return Add(N(K.TypeMetadataLazyCache), DemangleType(depth + 1));
                if (NextIf('m')) return Add(N(K.Metaclass), DemangleType(depth + 1));
                if (NextIf('n')) return Add(N(K.NominalTypeDescriptor), DemangleType(depth + 1));
                if (NextIf('f')) return Add(N(K.FullTypeMetadata), DemangleType(depth + 1));
                if (NextIf('p')) return Add(N(K.ProtocolDescriptor), DemangleProtocolName(depth + 1));
                return Add(N(K.TypeMetadata), DemangleType(depth + 1));
            }
            if (NextIf("PA"))
            {
                var forwarder = N(NextIf('o') ? K.PartialApplyObjCForwarder : K.PartialApplyForwarder);
                if (NextIf("__T")) return Add(forwarder, DemangleGlobal(depth + 1));
                return forwarder;
            }
            if (NextIf('t')) return Add(N(K.TypeMangling), DemangleType(depth + 1));
            if (NextIf('w'))
            {
                if (Empty) return null;
                char a = Next();
                if (Empty) return null;
                char b = Next();
                int w = Parser.ValueWitnessKind($"{a}{b}");
                if (w < 0) return null;
                var witness = N(K.ValueWitness);
                witness.Add(N(K.Index, (ulong)w));
                return Add(witness, DemangleType(depth + 1));
            }
            if (NextIf('W'))
            {
                if (NextIf('V')) return Add(N(K.ValueWitnessTable), DemangleType(depth + 1));
                if (NextIf('v'))
                {
                    var fieldOffset = N(K.FieldOffset);
                    if (NextIf('d')) fieldOffset.Add(N(K.Directness, 0UL));
                    else if (NextIf('i')) fieldOffset.Add(N(K.Directness, 1UL));
                    else return null;
                    return Add(fieldOffset, DemangleEntity(depth + 1));
                }
                if (NextIf('P')) return Add(N(K.ProtocolWitnessTable), DemangleProtocolConformance(depth + 1));
                if (NextIf('G')) return Add(N(K.GenericProtocolWitnessTable), DemangleProtocolConformance(depth + 1));
                if (NextIf('I')) return Add(N(K.GenericProtocolWitnessTableInstantiationFunction), DemangleProtocolConformance(depth + 1));
                if (NextIf('l') || (Peek() == 'L' && NextIf('L')))
                {
                    var accessor = N(text[pos - 1] == 'l' ? K.LazyProtocolWitnessTableAccessor : K.LazyProtocolWitnessTableCacheVariable);
                    if (Add(accessor, DemangleType(depth + 1)) == null) return null;
                    return Add(accessor, DemangleProtocolConformance(depth + 1));
                }
                if (NextIf('a')) return Add(N(K.ProtocolWitnessTableAccessor), DemangleProtocolConformance(depth + 1));
                if (NextIf('t'))
                {
                    var accessor = N(K.AssociatedTypeMetadataAccessor);
                    if (Add(accessor, DemangleProtocolConformance(depth + 1)) == null) return null;
                    return Add(accessor, DemangleDeclName(depth + 1));
                }
                if (NextIf('T'))
                {
                    var accessor = N(K.AssociatedTypeWitnessTableAccessor);
                    if (Add(accessor, DemangleProtocolConformance(depth + 1)) == null) return null;
                    if (Add(accessor, DemangleDeclName(depth + 1)) == null) return null;
                    return Add(accessor, DemangleProtocolName(depth + 1));
                }
                return null;
            }
            if (NextIf('T'))
            {
                if (NextIf('R'))
                {
                    var thunk = N(K.ReabstractionThunkHelper);
                    return DemangleReabstractSignature(thunk, depth + 1) ? thunk : null;
                }
                if (NextIf('r'))
                {
                    var thunk = N(K.ReabstractionThunk);
                    return DemangleReabstractSignature(thunk, depth + 1) ? thunk : null;
                }
                if (NextIf('W'))
                {
                    var thunk = N(K.ProtocolWitness);
                    if (Add(thunk, DemangleProtocolConformance(depth + 1)) == null) return null;
                    return Add(thunk, DemangleEntity(depth + 1));
                }
                return null;
            }
            return DemangleEntity(depth + 1);
        }

        private SwiftNode? DemangleGenericSpecialization(SwiftNode spec, int depth)
        {
            if (depth > MaxDepth) return null;
            while (!NextIf('_'))
            {
                var param = N(K.GenericSpecializationParam);
                if (Add(param, DemangleType(depth + 1)) == null) return null;
                while (!NextIf('_'))
                    if (Add(param, DemangleProtocolConformance(depth + 1)) == null) return null;
                spec.Add(param);
            }
            return spec;
        }

        private SwiftNode ParamKind(FuncSigParamKind k) => N(K.FunctionSignatureSpecializationParamKind, (ulong)k);

        private bool DemangleFuncSigSpecializationConstantProp(SwiftNode parent, int depth)
        {
            if (NextIf("fr") || NextIf('g'))
            {
                bool function = text[pos - 1] == 'r';
                var name = DemangleIdentifier(depth + 1);
                if (name == null || !NextIf('_')) return false;
                parent.Add(ParamKind(function ? FuncSigParamKind.ConstantPropFunction : FuncSigParamKind.ConstantPropGlobal));
                parent.Add(N(K.Identifier, name.Text!));
                return true;
            }
            if (NextIf('i') || NextIf("fl"))
            {
                bool integer = text[pos - 1] == 'i';
                var str = new StringBuilder();
                if (!ReadUntil('_', str) || !NextIf('_')) return false;
                parent.Add(ParamKind(integer ? FuncSigParamKind.ConstantPropInteger : FuncSigParamKind.ConstantPropFloat));
                parent.Add(N(K.FunctionSignatureSpecializationParamPayload, str.ToString()));
                return true;
            }
            if (NextIf('s'))
            {
                if (!NextIf('e')) return false;
                char encoding = Peek();
                if (encoding is not ('0' or '1')) return false;
                pos++;
                if (!NextIf('v')) return false;
                var str = DemangleIdentifier(depth + 1);
                if (str == null || !NextIf('_')) return false;
                parent.Add(ParamKind(FuncSigParamKind.ConstantPropString));
                parent.Add(N(K.FunctionSignatureSpecializationParamPayload, encoding == '0' ? "u8" : "u16"));
                parent.Add(N(K.Identifier, str.Text!));
                return true;
            }
            return false;
        }

        private bool DemangleFuncSigSpecializationClosureProp(SwiftNode parent, int depth)
        {
            var name = DemangleIdentifier(depth + 1);
            if (name == null) return false;
            parent.Add(ParamKind(FuncSigParamKind.ClosureProp));
            parent.Add(N(K.FunctionSignatureSpecializationParamPayload, name.Text!));
            SwiftNode? type;
            while (Peek() != '_' && (type = DemangleType(depth + 1)) != null) parent.Add(type);
            return NextIf('_');
        }

        private SwiftNode? DemangleFunctionSignatureSpecialization(SwiftNode spec, int depth)
        {
            while (!NextIf('_'))
            {
                var param = N(K.FunctionSignatureSpecializationParam);
                if (NextIf("n_")) { }
                else if (NextIf("cp"))
                {
                    if (!DemangleFuncSigSpecializationConstantProp(param, depth + 1)) return null;
                }
                else if (NextIf("cl"))
                {
                    if (!DemangleFuncSigSpecializationClosureProp(param, depth + 1)) return null;
                }
                else if (NextIf("i_")) param.Add(ParamKind(FuncSigParamKind.BoxToValue));
                else if (NextIf("k_")) param.Add(ParamKind(FuncSigParamKind.BoxToStack));
                else if (NextIf("r_")) param.Add(ParamKind(FuncSigParamKind.InOutToOut));
                else
                {
                    FuncSigParamKind value = 0;
                    if (NextIf('d')) value |= FuncSigParamKind.Dead;
                    if (NextIf('g')) value |= FuncSigParamKind.OwnedToGuaranteed;
                    if (NextIf('o')) value |= FuncSigParamKind.GuaranteedToOwned;
                    if (NextIf('s')) value |= FuncSigParamKind.SROA;
                    if (!NextIf('_') || value == 0) return null;
                    param.Add(ParamKind(value));
                }
                spec.Add(param);
            }
            return spec;
        }

        private SwiftNode? DemangleSpecializedAttribute(int depth)
        {
            bool notReAbstracted = false;
            if (NextIf('g') || (notReAbstracted = NextIf('r')))
            {
                var spec = N(notReAbstracted ? K.GenericSpecializationNotReAbstracted : K.GenericSpecialization);
                if (NextIf('q')) spec.Add(N(K.IsSerialized));
                spec.Add(N(K.SpecializationPassID, unchecked((ulong)(Next() - 48))));
                return DemangleGenericSpecialization(spec, depth + 1);
            }
            if (NextIf('f'))
            {
                var spec = N(K.FunctionSignatureSpecialization);
                if (NextIf('q')) spec.Add(N(K.IsSerialized));
                spec.Add(N(K.SpecializationPassID, unchecked((ulong)(Next() - 48))));
                return DemangleFunctionSignatureSpecialization(spec, depth + 1);
            }
            return null;
        }

        private SwiftNode? DemangleDeclName(int depth)
        {
            if (NextIf('L'))
            {
                var discriminator = DemangleIndexAsNode();
                if (discriminator == null) return null;
                var name = DemangleIdentifier(depth + 1);
                if (name == null) return null;
                var local = N(K.LocalDeclName);
                local.Add(discriminator);
                local.Add(name);
                return local;
            }
            if (NextIf('P'))
            {
                var discriminator = DemangleIdentifier(depth + 1);
                if (discriminator == null) return null;
                var name = DemangleIdentifier(depth + 1);
                if (name == null) return null;
                var priv = N(K.PrivateDeclName);
                priv.Add(discriminator);
                priv.Add(name);
                return priv;
            }
            return DemangleIdentifier(depth + 1);
        }

        private const string OperatorChars = "& @/= >    <*!|+?%-~   ^ .";

        private SwiftNode? DemangleIdentifier(int depth, K? kind = null)
        {
            if (Empty) return null;
            bool punycoded = NextIf('X');
            bool isOperator = false;
            if (NextIf('o'))
            {
                isOperator = true;
                if (kind != null) return null;
                kind = Next() switch { 'p' => K.PrefixOperator, 'P' => K.PostfixOperator, 'i' => K.InfixOperator, _ => null };
                if (kind == null) return null;
            }
            kind ??= K.Identifier;
            if (!DemangleNatural(out ulong length) || length > (ulong)(text.Length - pos)) return null;
            string identifier = text.Substring(pos, (int)length);
            pos += (int)length;
            if (punycoded)
            {
                if (Punycode.Decode(identifier) is not { } decoded) return null;
                identifier = decoded;
            }
            if (identifier.Length == 0) return null;
            if (isOperator)
            {
                var op = new StringBuilder(identifier.Length);
                foreach (char c in identifier)
                {
                    if (c >= 0x80)
                    {
                        op.Append(c);
                        continue;
                    }
                    if (c is < 'a' or > 'z') return null;
                    char o = OperatorChars[c - 'a'];
                    if (o == ' ') return null;
                    op.Append(o);
                }
                identifier = op.ToString();
            }
            return N(kind.Value, identifier);
        }

        private bool DemangleIndex(out ulong natural)
        {
            if (NextIf('_'))
            {
                natural = 0;
                return true;
            }
            if (DemangleNatural(out natural))
            {
                if (!NextIf('_')) return false;
                natural++;
                return true;
            }
            return false;
        }

        private SwiftNode? DemangleIndexAsNode(K kind = K.Number) => DemangleIndex(out ulong index) ? N(kind, index) : null;

        private SwiftNode CreateSwiftType(K kind, string name)
        {
            var type = N(kind);
            type.Add(N(K.Module, "Swift"));
            type.Add(N(K.Identifier, name));
            return type;
        }

        private SwiftNode? DemangleSubstitutionIndex()
        {
            if (Empty) return null;
            if (NextIf('o')) return N(K.Module, "__C");
            if (NextIf('C')) return N(K.Module, "__C_Synthesized");
            (K, string)? std = Peek() switch
            {
                'a' => (K.Structure, "Array"),
                'b' => (K.Structure, "Bool"),
                'c' => (K.Structure, "UnicodeScalar"),
                'd' => (K.Structure, "Double"),
                'f' => (K.Structure, "Float"),
                'i' => (K.Structure, "Int"),
                'V' => (K.Structure, "UnsafeRawPointer"),
                'v' => (K.Structure, "UnsafeMutableRawPointer"),
                'P' => (K.Structure, "UnsafePointer"),
                'p' => (K.Structure, "UnsafeMutablePointer"),
                'q' => (K.Enum, "Optional"),
                'Q' => (K.Enum, "ImplicitlyUnwrappedOptional"),
                'R' => (K.Structure, "UnsafeBufferPointer"),
                'r' => (K.Structure, "UnsafeMutableBufferPointer"),
                'S' => (K.Structure, "String"),
                'u' => (K.Structure, "UInt"),
                _ => null,
            };
            if (std is { } s)
            {
                pos++;
                return CreateSwiftType(s.Item1, s.Item2);
            }
            if (!DemangleIndex(out ulong index) || index >= (ulong)subs.Count) return null;
            return subs[(int)index];
        }

        private SwiftNode? DemangleModule(int depth)
        {
            if (NextIf('s')) return N(K.Module, "Swift");
            if (NextIf('S'))
            {
                var module = DemangleSubstitutionIndex();
                return module is { Kind: K.Module } ? module : null;
            }
            var mod = DemangleIdentifier(depth + 1, K.Module);
            if (mod == null) return null;
            subs.Add(mod);
            return mod;
        }

        private SwiftNode? DemangleDeclarationName(K kind, int depth)
        {
            var context = DemangleContext(depth + 1);
            if (context == null) return null;
            var name = DemangleDeclName(depth + 1);
            if (name == null) return null;
            var decl = N(kind);
            decl.Add(context);
            decl.Add(name);
            subs.Add(decl);
            return decl;
        }

        private SwiftNode? DemangleProtocolName(int depth)
        {
            var proto = DemangleProtocolNameImpl(depth);
            if (proto == null) return null;
            var type = N(K.Type);
            type.Add(proto);
            return type;
        }

        private SwiftNode? DemangleProtocolNameGivenContext(SwiftNode context, int depth)
        {
            var name = DemangleDeclName(depth + 1);
            if (name == null) return null;
            var proto = N(K.Protocol);
            proto.Add(context);
            proto.Add(name);
            subs.Add(proto);
            return proto;
        }

        private SwiftNode? DemangleProtocolNameImpl(int depth)
        {
            CheckStack();
            if (depth > MaxDepth) return null;
            if (NextIf('S'))
            {
                var sub = DemangleSubstitutionIndex();
                if (sub == null) return null;
                if (sub.Kind == K.Protocol) return sub;
                if (sub.Kind != K.Module) return null;
                return DemangleProtocolNameGivenContext(sub, depth + 1);
            }
            if (NextIf('s')) return DemangleProtocolNameGivenContext(N(K.Module, "Swift"), depth + 1);
            return DemangleDeclarationName(K.Protocol, depth + 1);
        }

        private SwiftNode? DemangleNominalType(int depth)
        {
            if (NextIf('S')) return DemangleSubstitutionIndex();
            if (NextIf('V')) return DemangleDeclarationName(K.Structure, depth + 1);
            if (NextIf('O')) return DemangleDeclarationName(K.Enum, depth + 1);
            if (NextIf('C')) return DemangleDeclarationName(K.Class, depth + 1);
            if (NextIf('P')) return DemangleDeclarationName(K.Protocol, depth + 1);
            return null;
        }

        private SwiftNode? DemangleBoundGenericArgs(SwiftNode nominal, int depth)
        {
            CheckStack();
            if (nominal.Count == 0) return null;
            var parentOrModule = nominal[0]!;
            if (parentOrModule.Kind is not (K.Module or K.Function or K.Extension))
            {
                parentOrModule = DemangleBoundGenericArgs(parentOrModule, depth + 1);
                if (parentOrModule == null) return null;
                var rebuilt = N(nominal.Kind);
                rebuilt.Add(parentOrModule);
                for (int i = 1; i < nominal.Count; i++) rebuilt.Add(nominal[i]!);
                nominal = rebuilt;
            }
            var args = N(K.TypeList);
            while (!NextIf('_'))
            {
                var type = DemangleType(depth + 1);
                if (type == null) return null;
                args.Add(type);
                if (Empty) return null;
            }
            if (args.Count == 0) return nominal;
            var unbound = N(K.Type);
            unbound.Add(nominal);
            K kind;
            switch (nominal.Kind)
            {
                case K.Class: kind = K.BoundGenericClass; break;
                case K.Structure: kind = K.BoundGenericStructure; break;
                case K.Enum: kind = K.BoundGenericEnum; break;
                default: return null;
            }
            var result = N(kind);
            result.Add(unbound);
            result.Add(args);
            return result;
        }

        private SwiftNode? DemangleBoundGenericType(int depth)
        {
            var nominal = DemangleNominalType(depth + 1);
            return nominal == null ? null : DemangleBoundGenericArgs(nominal, depth + 1);
        }

        private static bool IsStartOfIdentifier(char c) => c is >= '0' and <= '9' or 'o';
        private static bool IsStartOfNominalType(char c) => c is 'C' or 'V' or 'O';
        private static bool IsStartOfEntity(char c) => c is 'F' or 'I' or 'v' or 'P' or 's' or 'Z' || IsStartOfNominalType(c);

        private SwiftNode? DemangleContext(int depth)
        {
            CheckStack();
            if (Empty) return null;
            if (NextIf('E'))
            {
                var ext = N(K.Extension);
                var module = DemangleModule(depth + 1);
                if (module == null) return null;
                var type = DemangleContext(depth + 1);
                if (type == null) return null;
                ext.Add(module);
                ext.Add(type);
                return ext;
            }
            if (NextIf('e'))
            {
                var ext = N(K.Extension);
                var module = DemangleModule(depth + 1);
                if (module == null) return null;
                var sig = DemangleGenericSignature(depth + 1);
                if (sig == null) return null;
                var type = DemangleContext(depth + 1);
                if (type == null) return null;
                ext.Add(module);
                ext.Add(type);
                ext.Add(sig);
                return ext;
            }
            if (NextIf('S')) return DemangleSubstitutionIndex();
            if (NextIf('s')) return N(K.Module, "Swift");
            if (NextIf('G')) return DemangleBoundGenericType(depth + 1);
            if (IsStartOfEntity(Peek())) return DemangleEntity(depth + 1);
            return DemangleModule(depth + 1);
        }

        private SwiftNode? DemangleProtocolList(int depth)
        {
            var protoList = N(K.ProtocolList);
            var typeList = N(K.TypeList);
            protoList.Add(typeList);
            while (!NextIf('_'))
            {
                var proto = DemangleProtocolName(depth + 1);
                if (proto == null) return null;
                typeList.Add(proto);
            }
            return protoList;
        }

        private SwiftNode? DemangleProtocolConformance(int depth)
        {
            var type = DemangleType(depth + 1);
            if (type == null) return null;
            var protocol = DemangleProtocolName(depth + 1);
            if (protocol == null) return null;
            var context = DemangleContext(depth + 1);
            if (context == null) return null;
            var conf = N(K.ProtocolConformance);
            conf.Add(type);
            conf.Add(protocol);
            conf.Add(context);
            return conf;
        }

        private SwiftNode? DemangleEntity(int depth)
        {
            CheckStack();
            if (depth > MaxDepth) return null;
            bool isStatic = NextIf('Z');
            K basicKind;
            if (NextIf('F')) basicKind = K.Function;
            else if (NextIf('v')) basicKind = K.Variable;
            else if (NextIf('I')) basicKind = K.Initializer;
            else if (NextIf('i')) basicKind = K.Subscript;
            else return DemangleNominalType(depth + 1);

            var context = DemangleContext(depth + 1);
            if (context == null) return null;
            K kind;
            bool hasType = true, wrap = false;
            SwiftNode? name = null;
            if (NextIf('D')) { kind = K.Deallocator; hasType = false; }
            else if (NextIf('Z')) { kind = K.IsolatedDeallocator; hasType = false; }
            else if (NextIf('d')) { kind = K.Destructor; hasType = false; }
            else if (NextIf('e')) { kind = K.IVarInitializer; hasType = false; }
            else if (NextIf('E')) { kind = K.IVarDestroyer; hasType = false; }
            else if (NextIf('C')) kind = K.Allocator;
            else if (NextIf('c')) kind = K.Constructor;
            else if (NextIf('a') || NextIf('l'))
            {
                bool mutable = text[pos - 1] == 'a';
                wrap = true;
                if (NextIf('O')) kind = mutable ? K.OwningMutableAddressor : K.OwningAddressor;
                else if (NextIf('o')) kind = mutable ? K.NativeOwningMutableAddressor : K.NativeOwningAddressor;
                else if (NextIf('p')) kind = mutable ? K.NativePinningMutableAddressor : K.NativePinningAddressor;
                else if (NextIf('u')) kind = mutable ? K.UnsafeMutableAddressor : K.UnsafeAddressor;
                else return null;
                name = DemangleDeclName(depth + 1);
                if (name == null) return null;
            }
            else if (Peek() is 'g' or 'G' or 's' or 'm' or 'w' or 'W' or 'r' or 'M')
            {
                kind = Next() switch
                {
                    'g' => K.Getter,
                    'G' => K.GlobalGetter,
                    's' => K.Setter,
                    'm' => K.MaterializeForSet,
                    'w' => K.WillSet,
                    'W' => K.DidSet,
                    'r' => K.ReadAccessor,
                    _ => K.ModifyAccessor,
                };
                wrap = true;
                name = DemangleDeclName(depth + 1);
                if (name == null) return null;
            }
            else if (NextIf('U'))
            {
                kind = K.ExplicitClosure;
                name = DemangleIndexAsNode();
                if (name == null) return null;
            }
            else if (NextIf('u'))
            {
                kind = K.ImplicitClosure;
                name = DemangleIndexAsNode();
                if (name == null) return null;
            }
            else if (basicKind == K.Initializer)
            {
                if (NextIf('A'))
                {
                    kind = K.DefaultArgumentInitializer;
                    name = DemangleIndexAsNode();
                    if (name == null) return null;
                }
                else if (NextIf('i')) kind = K.Initializer;
                else return null;
                hasType = false;
            }
            else
            {
                kind = basicKind;
                name = DemangleDeclName(depth + 1);
                if (name == null) return null;
            }

            var entity = N(kind);
            if (wrap)
            {
                bool isSubscript = false;
                if (name!.Kind == K.Identifier)
                {
                    if (name.Text == "subscript")
                    {
                        isSubscript = true;
                        name = null;
                    }
                }
                else if (name.Kind == K.PrivateDeclName && name.Count > 1 && name[1]!.Text == "subscript")
                {
                    isSubscript = true;
                    var discriminator = name[0]!;
                    name = N(K.PrivateDeclName);
                    name.Add(discriminator);
                }
                var wrapped = N(isSubscript ? K.Subscript : K.Variable);
                wrapped.Add(context);
                if (!isSubscript) wrapped.Add(name!);
                if (hasType)
                {
                    var type = DemangleType(depth + 1);
                    if (type == null) return null;
                    wrapped.Add(type);
                }
                if (isSubscript && name != null) wrapped.Add(name);
                entity.Add(wrapped);
            }
            else
            {
                entity.Add(context);
                if (name != null) entity.Add(name);
                if (hasType)
                {
                    var type = DemangleType(depth + 1);
                    if (type == null) return null;
                    entity.Add(type);
                }
            }
            if (!isStatic) return entity;
            var staticNode = N(K.Static);
            staticNode.Add(entity);
            return staticNode;
        }

        private SwiftNode GetDependentGenericParamType(ulong depth, ulong index)
        {
            var p = N(K.DependentGenericParamType);
            p.Add(N(K.Index, depth));
            p.Add(N(K.Index, index));
            return p;
        }

        private SwiftNode? DemangleGenericParamIndex()
        {
            ulong paramDepth, index;
            if (NextIf('d'))
            {
                if (!DemangleIndex(out paramDepth)) return null;
                paramDepth++;
                if (!DemangleIndex(out index)) return null;
            }
            else if (NextIf('x'))
            {
                paramDepth = 0;
                index = 0;
            }
            else
            {
                if (!DemangleIndex(out index)) return null;
                paramDepth = 0;
                index++;
            }
            return GetDependentGenericParamType(paramDepth, index);
        }

        private SwiftNode? DemangleDependentMemberTypeName(SwiftNode baseType, int depth)
        {
            SwiftNode? assoc;
            if (NextIf('S'))
            {
                assoc = DemangleSubstitutionIndex();
                if (assoc == null || assoc.Kind != K.DependentAssociatedTypeRef) return null;
            }
            else
            {
                SwiftNode? protocol = null;
                if (NextIf('P'))
                {
                    protocol = DemangleProtocolName(depth + 1);
                    if (protocol == null) return null;
                }
                var id = DemangleIdentifier(depth + 1);
                if (id == null) return null;
                assoc = N(K.DependentAssociatedTypeRef);
                assoc.Add(id);
                if (protocol != null) assoc.Add(protocol);
                subs.Add(assoc);
            }
            var dep = N(K.DependentMemberType);
            dep.Add(baseType);
            dep.Add(assoc);
            return dep;
        }

        private SwiftNode? DemangleAssociatedTypeSimple(int depth)
        {
            var baseNode = DemangleGenericParamIndex();
            if (baseNode == null) return null;
            var type = N(K.Type);
            type.Add(baseNode);
            return DemangleDependentMemberTypeName(type, depth + 1);
        }

        private SwiftNode? DemangleAssociatedTypeCompound(int depth)
        {
            var baseNode = DemangleGenericParamIndex();
            if (baseNode == null) return null;
            while (!NextIf('_'))
            {
                var type = N(K.Type);
                type.Add(baseNode);
                baseNode = DemangleDependentMemberTypeName(type, depth + 1);
                if (baseNode == null) return null;
            }
            return baseNode;
        }

        private SwiftNode? DemangleDependentType(int depth)
        {
            if (Empty) return null;
            char c = Peek();
            if (c != 'd' && c != '_' && c is not (>= '0' and <= '9'))
            {
                var baseType = DemangleType(depth + 1);
                return baseType == null ? null : DemangleDependentMemberTypeName(baseType, depth + 1);
            }
            return DemangleGenericParamIndex();
        }

        private SwiftNode? DemangleConstrainedType(int depth)
        {
            var type = NextIf('w') ? DemangleAssociatedTypeSimple(depth + 1) : NextIf('W') ? DemangleAssociatedTypeCompound(depth + 1) : DemangleGenericParamIndex();
            if (type == null) return null;
            var node = N(K.Type);
            node.Add(type);
            return node;
        }

        private SwiftNode? DemangleGenericSignature(int depth, bool pseudogeneric = false)
        {
            var sig = N(pseudogeneric ? K.DependentPseudogenericSignature : K.DependentGenericSignature);
            ulong count = ulong.MaxValue;
            while (Peek() != 'R' && Peek() != 'r')
            {
                if (NextIf('z')) count = 0;
                else if (DemangleIndex(out count)) count++;
                else return null;
                sig.Add(N(K.DependentGenericParamCount, count));
            }
            if (count == ulong.MaxValue) sig.Add(N(K.DependentGenericParamCount, 1UL));
            if (NextIf('r')) return sig;
            if (!NextIf('R')) return null;
            while (!NextIf('r'))
            {
                var reqt = DemangleGenericRequirement(depth + 1);
                if (reqt == null) return null;
                sig.Add(reqt);
            }
            return sig;
        }

        private SwiftNode? DemangleMetatypeRepresentation()
        {
            if (NextIf('t')) return N(K.MetatypeRepresentation, "@thin");
            if (NextIf('T')) return N(K.MetatypeRepresentation, "@thick");
            if (NextIf('o')) return N(K.MetatypeRepresentation, "@objc_metatype");
            return null;
        }

        private SwiftNode? DemangleGenericRequirement(int depth)
        {
            var constrained = DemangleConstrainedType(depth + 1);
            if (constrained == null) return null;
            if (NextIf('z'))
            {
                var second = DemangleType(depth + 1);
                if (second == null) return null;
                var same = N(K.DependentGenericSameTypeRequirement);
                same.Add(constrained);
                same.Add(second);
                return same;
            }
            if (NextIf('l'))
            {
                ulong size = ulong.MaxValue, alignment = ulong.MaxValue;
                string name;
                char c = Next();
                switch (c)
                {
                    case 'U' or 'R' or 'N' or 'T' or 'B': name = c.ToString(); break;
                    case 'E' or 'M':
                        if (!DemangleNatural(out size) || !NextIf('_') || !DemangleNatural(out alignment)) return null;
                        name = c.ToString();
                        break;
                    case 'e' or 'm' or 'S':
                        if (!DemangleNatural(out size)) return null;
                        name = c.ToString();
                        break;
                    default: return null;
                }
                var reqt = N(K.DependentGenericLayoutRequirement);
                reqt.Add(constrained);
                reqt.Add(N(K.Identifier, name));
                if (size != ulong.MaxValue)
                {
                    reqt.Add(N(K.Number, size));
                    if (alignment != ulong.MaxValue) reqt.Add(N(K.Number, alignment));
                }
                return reqt;
            }
            if (Empty) return null;
            SwiftNode? constraint;
            char next = Peek();
            if (next == 'C')
            {
                constraint = DemangleType(depth + 1);
                if (constraint == null) return null;
            }
            else if (next == 'S')
            {
                Next();
                var sub = DemangleSubstitutionIndex();
                if (sub == null) return null;
                SwiftNode? typeName;
                if (sub.Kind is K.Protocol or K.Class) typeName = sub;
                else if (sub.Kind == K.Module)
                {
                    typeName = DemangleProtocolNameGivenContext(sub, depth + 1);
                    if (typeName == null) return null;
                }
                else return null;
                constraint = N(K.Type);
                constraint.Add(typeName);
            }
            else
            {
                constraint = DemangleProtocolName(depth + 1);
                if (constraint == null) return null;
            }
            var conformance = N(K.DependentGenericConformanceRequirement);
            conformance.Add(constrained);
            conformance.Add(constraint);
            return conformance;
        }

        private SwiftNode? DemangleArchetypeType(int depth)
        {
            CheckStack();
            SwiftNode? MakeAssociatedType(SwiftNode root)
            {
                var name = DemangleIdentifier(depth + 1);
                if (name == null) return null;
                var assoc = N(K.AssociatedTypeRef);
                assoc.Add(root);
                assoc.Add(name);
                subs.Add(assoc);
                return assoc;
            }
            if (NextIf('Q'))
            {
                var root = DemangleArchetypeType(depth + 1);
                return root == null ? null : MakeAssociatedType(root);
            }
            if (NextIf('S'))
            {
                var sub = DemangleSubstitutionIndex();
                return sub == null ? null : MakeAssociatedType(sub);
            }
            if (NextIf('s')) return MakeAssociatedType(N(K.Module, "Swift"));
            return null;
        }

        private SwiftNode? DemangleTuple(bool variadic, int depth)
        {
            var tuple = N(K.Tuple);
            SwiftNode? elt = null;
            while (!NextIf('_'))
            {
                if (Empty) return null;
                elt = N(K.TupleElement);
                if (IsStartOfIdentifier(Peek()))
                {
                    var label = DemangleIdentifier(depth + 1, K.TupleElementName);
                    if (label == null) return null;
                    elt.Add(label);
                }
                var type = DemangleType(depth + 1);
                if (type == null) return null;
                elt.Add(type);
                tuple.Add(elt);
            }
            if (variadic && elt != null)
            {
                elt.Reverse();
                elt.Add(N(K.VariadicMarker));
                elt.Reverse();
            }
            return tuple;
        }

        private SwiftNode? DemangleType(int depth)
        {
            var type = DemangleTypeImpl(depth);
            if (type == null) return null;
            var node = N(K.Type);
            node.Add(type);
            return node;
        }

        private SwiftNode? DemangleFunctionType(K kind, int depth)
        {
            bool throws = false, concurrent = false, isAsync = false;
            char diffKind = '\0';
            SwiftNode? globalActor = null;
            if (!Empty)
            {
                throws = NextIf('z');
                concurrent = NextIf('y');
                isAsync = NextIf('Z');
                if (NextIf('D'))
                {
                    char d = Next();
                    if (d is 'f' or 'r' or 'd' or 'l') diffKind = d;
                }
                if (NextIf('Y'))
                {
                    globalActor = DemangleType(depth + 1);
                    if (globalActor == null) return null;
                }
            }
            var inArgs = DemangleType(depth + 1);
            if (inArgs == null) return null;
            var outArgs = DemangleType(depth + 1);
            if (outArgs == null) return null;
            var block = N(kind);
            if (throws) block.Add(N(K.ThrowsAnnotation));
            if (isAsync) block.Add(N(K.AsyncAnnotation));
            if (concurrent) block.Add(N(K.ConcurrentFunctionType));
            if (diffKind != '\0') block.Add(N(K.DifferentiableFunctionType, diffKind));
            if (globalActor != null)
            {
                var actor = N(K.GlobalActorFunctionType);
                actor.Add(globalActor);
                block.Add(actor);
            }
            var inNode = N(K.ArgumentTuple);
            block.Add(inNode);
            inNode.Add(inArgs);
            var outNode = N(K.ReturnType);
            outNode.Add(outArgs);
            block.Add(outNode);
            return block;
        }

        private SwiftNode? Wrap(K kind, SwiftNode? child)
        {
            if (child == null) return null;
            var n = N(kind);
            n.Add(child);
            return n;
        }

        private SwiftNode? DemangleTypeImpl(int depth)
        {
            CheckStack();
            if (depth > MaxDepth || Empty) return null;
            char c = Next();
            switch (c)
            {
                case 'B':
                {
                    if (Empty) return null;
                    c = Next();
                    switch (c)
                    {
                        case 'b': return N(K.BuiltinTypeName, "Builtin.BridgeObject");
                        case 'B': return N(K.BuiltinTypeName, "Builtin.UnsafeValueBuffer");
                        case 'f':
                            return DemangleBuiltinSize(out ulong fsize) ? N(K.BuiltinTypeName, "Builtin.FPIEEE" + fsize) : null;
                        case 'i':
                            return DemangleBuiltinSize(out ulong isize) ? N(K.BuiltinTypeName, "Builtin.Int" + isize) : null;
                        case 'v':
                            if (DemangleNatural(out ulong elts))
                            {
                                if (!NextIf('B')) return null;
                                if (NextIf('i')) return DemangleBuiltinSize(out ulong s) ? N(K.BuiltinTypeName, $"Builtin.Vec{elts}xInt{s}") : null;
                                if (NextIf('f')) return DemangleBuiltinSize(out ulong s) ? N(K.BuiltinTypeName, $"Builtin.Vec{elts}xFPIEEE{s}") : null;
                                if (NextIf('p')) return N(K.BuiltinTypeName, $"Builtin.Vec{elts}xRawPointer");
                            }
                            return null;
                        case 'O': return N(K.BuiltinTypeName, "Builtin.UnknownObject");
                        case 'o': return N(K.BuiltinTypeName, "Builtin.NativeObject");
                        case 'p': return N(K.BuiltinTypeName, "Builtin.RawPointer");
                        case 't': return N(K.BuiltinTypeName, "Builtin.SILToken");
                        case 'w': return N(K.BuiltinTypeName, "Builtin.Word");
                        default: return null;
                    }
                }
                case 'a': return DemangleDeclarationName(K.TypeAlias, depth + 1);
                case 'b': return DemangleFunctionType(K.ObjCBlock, depth + 1);
                case 'c': return DemangleFunctionType(K.CFunctionPointer, depth + 1);
                case 'D': return Wrap(K.DynamicSelf, DemangleType(depth + 1));
                case 'E':
                    if (!NextIf('R') || !NextIf('R')) return null;
                    return N(K.ErrorType, "");
                case 'F': return DemangleFunctionType(K.FunctionType, depth + 1);
                case 'f': return DemangleFunctionType(K.UncurriedFunctionType, depth + 1);
                case 'G': return DemangleBoundGenericType(depth + 1);
                case 'X':
                    if (NextIf('b')) return Wrap(K.SILBoxType, DemangleType(depth + 1));
                    if (NextIf('B'))
                    {
                        SwiftNode? signature = null;
                        if (NextIf('G'))
                        {
                            signature = DemangleGenericSignature(depth);
                            if (signature == null) return null;
                        }
                        var layout = N(K.SILBoxLayout);
                        while (!NextIf('_'))
                        {
                            K kind;
                            if (NextIf('m')) kind = K.SILBoxMutableField;
                            else if (NextIf('i')) kind = K.SILBoxImmutableField;
                            else return null;
                            var type = DemangleType(depth + 1);
                            if (type == null) return null;
                            var field = N(kind);
                            field.Add(type);
                            layout.Add(field);
                        }
                        SwiftNode? genericArgs = null;
                        if (signature != null)
                        {
                            genericArgs = N(K.TypeList);
                            while (!NextIf('_'))
                            {
                                var type = DemangleType(depth + 1);
                                if (type == null) return null;
                                genericArgs.Add(type);
                            }
                        }
                        var box = N(K.SILBoxTypeWithLayout);
                        box.Add(layout);
                        if (signature != null)
                        {
                            box.Add(signature);
                            box.Add(genericArgs!);
                        }
                        return box;
                    }
                    if (NextIf('M'))
                    {
                        var repr = DemangleMetatypeRepresentation();
                        if (repr == null) return null;
                        var type = DemangleType(depth + 1);
                        if (type == null) return null;
                        var metatype = N(K.Metatype);
                        metatype.Add(repr);
                        metatype.Add(type);
                        return metatype;
                    }
                    if (NextIf('P'))
                    {
                        if (NextIf('M'))
                        {
                            var repr = DemangleMetatypeRepresentation();
                            if (repr == null) return null;
                            var type = DemangleType(depth + 1);
                            if (type == null) return null;
                            var metatype = N(K.ExistentialMetatype);
                            metatype.Add(repr);
                            metatype.Add(type);
                            return metatype;
                        }
                        return DemangleProtocolList(depth + 1);
                    }
                    if (NextIf('f')) return DemangleFunctionType(K.ThinFunctionType, depth + 1);
                    if (NextIf('o')) return Wrap(K.Unowned, DemangleType(depth + 1));
                    if (NextIf('u')) return Wrap(K.Unmanaged, DemangleType(depth + 1));
                    if (NextIf('w')) return Wrap(K.Weak, DemangleType(depth + 1));
                    if (NextIf('F')) return DemangleImplFunctionType(depth + 1);
                    return null;
                case 'K': return DemangleFunctionType(K.AutoClosureType, depth + 1);
                case 'M': return Wrap(K.Metatype, DemangleType(depth + 1));
                case 'P':
                    if (NextIf('M')) return Wrap(K.ExistentialMetatype, DemangleType(depth + 1));
                    return DemangleProtocolList(depth + 1);
                case 'Q':
                    if (NextIf('u')) return N(K.OpaqueReturnType);
                    if (NextIf('U'))
                    {
                        if (!DemangleIndex(out ulong ordinal)) return null;
                        var result = N(K.OpaqueReturnType);
                        result.Add(N(K.OpaqueReturnTypeIndex, ordinal));
                        return result;
                    }
                    return DemangleArchetypeType(depth + 1);
                case 'q': return DemangleDependentType(depth + 1);
                case 'x': return GetDependentGenericParamType(0, 0);
                case 'w': return DemangleAssociatedTypeSimple(depth + 1);
                case 'W': return DemangleAssociatedTypeCompound(depth + 1);
                case 'R': return Wrap(K.InOut, DemangleTypeImpl(depth + 1));
                case 'k': return Wrap(K.NoDerivative, DemangleTypeImpl(depth + 1));
                case 'S': return DemangleSubstitutionIndex();
                case 'T': return DemangleTuple(false, depth + 1);
                case 't': return DemangleTuple(true, depth + 1);
                case 'u':
                {
                    var sig = DemangleGenericSignature(depth + 1);
                    if (sig == null) return null;
                    var sub = DemangleType(depth + 1);
                    if (sub == null) return null;
                    var dependent = N(K.DependentGenericType);
                    dependent.Add(sig);
                    dependent.Add(sub);
                    return dependent;
                }
                default:
                    if (IsStartOfNominalType(c))
                        return DemangleDeclarationName(c switch { 'C' => K.Class, 'V' => K.Structure, _ => K.Enum }, depth + 1);
                    return null;
            }
        }

        private bool DemangleReabstractSignature(SwiftNode signature, int depth)
        {
            if (NextIf('G'))
            {
                var generics = DemangleGenericSignature(depth + 1);
                if (generics == null) return false;
                signature.Add(generics);
            }
            var src = DemangleType(depth + 1);
            if (src == null) return false;
            signature.Add(src);
            var dest = DemangleType(depth + 1);
            if (dest == null) return false;
            signature.Add(dest);
            return true;
        }

        private SwiftNode? DemangleImplFunctionType(int depth)
        {
            var type = N(K.ImplFunctionType);
            string? callee = NextIf('t') ? "@convention(thin)" : DemangleImplConvention(0);
            if (string.IsNullOrEmpty(callee)) return null;
            type.Add(N(K.ImplConvention, callee));
            if (NextIf('C'))
            {
                string? conv = NextIf('b') ? "block" : NextIf('c') ? "c" : NextIf('m') ? "method" : NextIf('O') ? "objc_method" : NextIf('w') ? "witness_method" : null;
                if (conv == null) return null;
                var attr = N(K.ImplFunctionConvention);
                attr.Add(N(K.ImplFunctionConventionName, conv));
                type.Add(attr);
            }
            if (NextIf('h')) type.Add(N(K.ImplFunctionAttribute, "@Sendable"));
            if (NextIf('H')) type.Add(N(K.ImplFunctionAttribute, "@async"));
            bool pseudogeneric = false;
            if (NextIf('G') || (pseudogeneric = NextIf('g')))
            {
                var generics = DemangleGenericSignature(depth + 1, pseudogeneric);
                if (generics == null) return null;
                type.Add(generics);
            }
            if (!NextIf('_')) return null;
            while (!NextIf('_'))
            {
                var input = DemangleImplParameterOrResult(K.ImplParameter, depth + 1);
                if (input == null) return null;
                type.Add(input);
            }
            while (!NextIf('_'))
            {
                var result = DemangleImplParameterOrResult(K.ImplResult, depth + 1);
                if (result == null) return null;
                type.Add(result);
            }
            return type;
        }

        /// <summary>context: 0 callee, 1 parameter, 2 result; empty when the convention does not apply there.</summary>
        private string DemangleImplConvention(int context)
        {
            (char Code, string Callee, string Param, string Result)[] table =
            [
                ('a', "", "", "@autoreleased"),
                ('d', "@callee_unowned", "@unowned", "@unowned"),
                ('D', "", "", "@unowned_inner_pointer"),
                ('g', "@callee_guaranteed", "@guaranteed", ""),
                ('e', "", "@deallocating", ""),
                ('i', "", "@in", "@out"),
                ('l', "", "@inout", ""),
                ('o', "@callee_owned", "@owned", "@owned"),
            ];
            foreach (var row in table)
                if (NextIf(row.Code))
                    return context switch { 0 => row.Callee, 1 => row.Param, _ => row.Result };
            return "";
        }

        private SwiftNode? DemangleImplParameterOrResult(K kind, int depth)
        {
            if (NextIf('z'))
            {
                if (kind != K.ImplResult) return null;
                kind = K.ImplErrorResult;
            }
            var convention = DemangleImplConvention(kind == K.ImplParameter ? 1 : 2);
            if (convention.Length == 0) return null;
            var type = DemangleType(depth + 1);
            if (type == null) return null;
            var node = N(kind);
            node.Add(N(K.ImplConvention, convention));
            node.Add(type);
            return node;
        }
    }

    /// <summary>Swift's punycode variant: '_' delimits, digits a-z then A-J, and U+D800-D87F stand for ASCII symbol characters.</summary>
    internal static class Punycode
    {
        private const int Base = 36, TMin = 1, TMax = 26, Skew = 38, Damp = 700, InitialBias = 72;
        private const int InitialN = 128;

        private static int DigitIndex(char c) => c switch
        {
            >= 'a' and <= 'z' => c - 'a',
            >= 'A' and <= 'J' => c - 'A' + 26,
            _ => -1,
        };

        private static int Adapt(int delta, int numPoints, bool first)
        {
            delta = first ? delta / Damp : delta / 2;
            delta += delta / numPoints;
            int k = 0;
            while (delta > (Base - TMin) * TMax / 2)
            {
                delta /= Base - TMin;
                k += Base;
            }
            return k + (Base - TMin + 1) * delta / (delta + Skew);
        }

        /// <summary>The decoded identifier, or null when <paramref name="input"/> is not valid punycode.</summary>
        public static string? Decode(string input)
        {
            var output = new List<int>(input.Length);
            int n = InitialN, i = 0, bias = InitialBias;
            int last = input.LastIndexOf('_');
            if (last >= 0)
            {
                foreach (char c in input.AsSpan(0, last))
                {
                    if (c > 0x7F) return null;
                    output.Add(c);
                }
                input = input[(last + 1)..];
            }
            int at = 0;
            while (at < input.Length)
            {
                int oldi = i, w = 1;
                for (int k = Base; ; k += Base)
                {
                    if (at >= input.Length) return null;
                    int digit = DigitIndex(input[at++]);
                    if (digit < 0) return null;
                    if (digit > (int.MaxValue - i) / w) return null;
                    i += digit * w;
                    int t = k <= bias ? TMin : k >= bias + TMax ? TMax : k - bias;
                    if (digit < t) break;
                    if (w > int.MaxValue / (Base - t)) return null;
                    w *= Base - t;
                }
                bias = Adapt(i - oldi, output.Count + 1, oldi == 0);
                if (i / (output.Count + 1) > int.MaxValue - n) return null;
                n += i / (output.Count + 1);
                i %= output.Count + 1;
                if (n < 0x80) return null;
                output.Insert(i, n);
                i++;
            }
            var sb = new StringBuilder(output.Count);
            foreach (int cp in output)
            {
                if (cp >= 0xD880 && cp < 0xE000 || cp > 0x10FFFF) return null;
                if (cp is >= 0xD800 and < 0xD880) sb.Append((char)(cp - 0xD800));
                else sb.Append(char.ConvertFromUtf32(cp));
            }
            return sb.ToString();
        }
    }
}
