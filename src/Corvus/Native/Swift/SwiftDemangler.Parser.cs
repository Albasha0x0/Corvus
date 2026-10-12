using System.Text;
using K = Corvus.Native.Swift.SwiftNodeKind;

namespace Corvus.Native.Swift;

public static partial class SwiftDemangler
{
    /// <summary>The Swift 4+ mangling: a stack machine over operators, as the Swift runtime's demangler reads it.</summary>
    private sealed class Parser(string text, SymbolicResolver? resolver)
    {
        private const int MaxNumWords = 26;
        private const int MaxRepeatCount = 2048;
        private const int MaxIdentifierLength = 4 * 1024 * 1024;
        private const int MaxSpecializationPass = 10;

        private readonly List<SwiftNode> stack = [];
        private readonly List<SwiftNode> subs = [];
        private readonly string[] words = new string[MaxNumWords];
        private int numWords;
        private int pos;
        private bool oldFunctionTypeMangling;
        private int nodes;

        // ---- node factory ----

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

        private SwiftNode N(K kind, long index) => N(kind, unchecked((ulong)index));

        private static SwiftNode? AddChild(SwiftNode? parent, SwiftNode? child)
        {
            if (parent == null || child == null) return null;
            parent.Add(child);
            return parent;
        }

        private SwiftNode? With(K kind, SwiftNode? child)
        {
            if (child == null) return null;
            var n = N(kind);
            n.Add(child);
            return n;
        }

        private SwiftNode? With(K kind, SwiftNode? a, SwiftNode? b)
        {
            if (a == null || b == null) return null;
            var n = N(kind);
            n.Add(a);
            n.Add(b);
            return n;
        }

        private SwiftNode? With(K kind, SwiftNode? a, SwiftNode? b, SwiftNode? c)
        {
            if (a == null || b == null || c == null) return null;
            var n = N(kind);
            n.Add(a);
            n.Add(b);
            n.Add(c);
            return n;
        }

        private SwiftNode? With(K kind, SwiftNode? a, SwiftNode? b, SwiftNode? c, SwiftNode? d)
        {
            if (a == null || b == null || c == null || d == null) return null;
            var n = N(kind);
            n.Add(a);
            n.Add(b);
            n.Add(c);
            n.Add(d);
            return n;
        }

        private SwiftNode? CreateType(SwiftNode? child) => With(K.Type, child);
        private SwiftNode? WithPoppedType(K kind) => With(kind, Pop(K.Type));

        private SwiftNode? ChangeKind(SwiftNode? node, K kind)
        {
            if (node == null) return null;
            var n = node.HasText ? N(kind, node.Text!) : node.HasIndex ? N(kind, node.Index) : N(kind);
            foreach (var c in node.Children) n.Add(c);
            return n;
        }

        // ---- text ----

        private char Peek() => pos < text.Length ? text[pos] : '\0';

        private char Next() => pos < text.Length ? text[pos++] : '\0';

        private bool NextIf(char c)
        {
            if (Peek() != c) return false;
            pos++;
            return true;
        }

        private bool NextIf(string s)
        {
            if (string.CompareOrdinal(text, pos, s, 0, s.Length) != 0 || pos + s.Length > text.Length) return false;
            pos += s.Length;
            return true;
        }

        private void PushBack()
        {
            if (pos > 0) pos--;
        }

        private string ConsumeAll()
        {
            var s = text[pos..];
            pos = text.Length;
            return s;
        }

        // ---- stack ----

        private void Push(SwiftNode n) => stack.Add(n);

        private SwiftNode? Pop()
        {
            if (stack.Count == 0) return null;
            var n = stack[^1];
            stack.RemoveAt(stack.Count - 1);
            return n;
        }

        private SwiftNode? Pop(K kind) => stack.Count > 0 && stack[^1].Kind == kind ? Pop() : null;

        private SwiftNode? Pop(Func<K, bool> pred) => stack.Count > 0 && pred(stack[^1].Kind) ? Pop() : null;

        private void AddSubstitution(SwiftNode? n)
        {
            if (n != null) subs.Add(n);
        }

        // ---- entry points ----

        public SwiftNode? DemangleSymbol()
        {
            if (text.StartsWith("_Tt", StringComparison.Ordinal)) return new OldParser(text).DemangleTopLevel();
            int prefix = PrefixLength(text);
            if (prefix == 0)
            {
                int length = AsyncMainLength(text);
                if (length == 0) return null;
                pos += length;
                Push(N(K.AsyncMainEntryPoint));
            }
            else
            {
                oldFunctionTypeMangling = text.StartsWith("_T", StringComparison.Ordinal);
                pos += prefix;
            }
            if (!ParseAndPushNodes()) return null;

            var top = N(K.Global);
            var suffix = Pop(K.Suffix);
            var parent = top;
            while (Pop(IsFunctionAttr) is { } attr)
            {
                parent.Add(attr);
                if (attr.Kind is K.PartialApplyForwarder or K.PartialApplyObjCForwarder) parent = attr;
            }
            foreach (var nd in stack)
                parent.Add(nd.Kind == K.Type ? nd.First! : nd);
            if (suffix != null) top.Add(suffix);
            return top.Count == 0 ? null : top;
        }

        public SwiftNode? DemangleType()
        {
            if (!ParseAndPushNodes()) return null;
            var result = Pop();
            return Pop() != null ? null : result;
        }

        private bool ParseAndPushNodes()
        {
            while (pos < text.Length)
            {
                if (Peek() == '\0') return true;
                var node = DemangleOperator();
                if (node == null) return false;
                Push(node);
            }
            return true;
        }

        // ---- classification ----

        private static bool IsDeclName(K k) => k is K.Identifier or K.LocalDeclName or K.PrivateDeclName or K.RelatedEntityDeclName or K.PrefixOperator
            or K.PostfixOperator or K.InfixOperator or K.TypeSymbolicReference or K.ProtocolSymbolicReference or K.ObjectiveCProtocolSymbolicReference;

        private static bool IsAnyGeneric(K k) => k is K.Structure or K.Class or K.Enum or K.Protocol or K.ProtocolSymbolicReference
            or K.ObjectiveCProtocolSymbolicReference or K.OtherNominalType or K.TypeAlias or K.TypeSymbolicReference or K.BuiltinTupleType;

        private static bool IsEntity(K k) => k == K.Type || IsContext(k);

        private static bool IsRequirement(K k) => k is K.DependentGenericParamPackMarker or K.DependentGenericParamValueMarker or K.DependentGenericSameTypeRequirement
            or K.DependentGenericSameShapeRequirement or K.DependentGenericLayoutRequirement or K.DependentGenericConformanceRequirement
            or K.DependentGenericInverseConformanceRequirement;

        internal static bool IsContext(K k) => k is K.Allocator or K.AnonymousContext or K.Class or K.Constructor or K.Deallocator or K.DefaultArgumentInitializer
            or K.Destructor or K.DidSet or K.Enum or K.ExplicitClosure or K.Extension or K.Function or K.Getter or K.GlobalGetter or K.IVarInitializer
            or K.IVarDestroyer or K.ImplicitClosure or K.Initializer or K.InitAccessor or K.IsolatedDeallocator or K.MaterializeForSet or K.ModifyAccessor
            or K.YieldingMutateAccessor or K.Module or K.NativeOwningAddressor or K.NativeOwningMutableAddressor or K.NativePinningAddressor
            or K.NativePinningMutableAddressor or K.OtherNominalType or K.OwningAddressor or K.OwningMutableAddressor or K.PropertyWrapperBackingInitializer
            or K.PropertyWrappedFieldInitAccessor or K.PropertyWrapperInitFromProjectedValue or K.Protocol or K.ProtocolSymbolicReference or K.ReadAccessor
            or K.YieldingBorrowAccessor or K.Setter or K.Static or K.Structure or K.Subscript or K.TypeSymbolicReference or K.TypeAlias or K.UnsafeAddressor
            or K.UnsafeMutableAddressor or K.Variable or K.WillSet or K.OpaqueReturnTypeOf or K.AutoDiffFunction or K.BorrowAccessor or K.MutateAccessor
            or K.BuiltinTupleType;

        internal static bool IsFunctionAttr(K k) => k is K.FunctionSignatureSpecialization or K.GenericSpecialization or K.GenericSpecializationPrespecialized
            or K.InlinedGenericFunction or K.GenericSpecializationNotReAbstracted or K.GenericPartialSpecialization or K.GenericPartialSpecializationNotReAbstracted
            or K.GenericSpecializationInResilienceDomain or K.ObjCAttribute or K.NonObjCAttribute or K.DynamicAttribute or K.DirectMethodReferenceAttribute
            or K.VTableAttribute or K.PartialApplyForwarder or K.PartialApplyObjCForwarder or K.OutlinedVariable or K.OutlinedReadOnlyObject
            or K.OutlinedBridgedMethod or K.MergedFunction or K.DistributedThunk or K.DistributedAccessor or K.DynamicallyReplaceableFunctionImpl
            or K.DynamicallyReplaceableFunctionKey or K.DynamicallyReplaceableFunctionVar or K.AsyncFunctionPointer or K.AsyncAwaitResumePartialFunction
            or K.AsyncSuspendResumePartialFunction or K.AccessibleFunctionRecord or K.BackDeploymentThunk or K.BackDeploymentFallback or K.HasSymbolQuery
            or K.CoroFunctionPointer or K.DefaultOverride;

        private static bool IsProtocolNode(SwiftNode? n) => n != null && (n.Kind == K.Type ? IsProtocolNode(n.First)
            : n.Kind is K.Protocol or K.ProtocolSymbolicReference or K.ObjectiveCProtocolSymbolicReference);

        private static bool IsGenericParamType(SwiftNode? n) => n != null && (n.Kind == K.Type ? IsGenericParamType(n.First) : n.Kind == K.DependentGenericParamType);

        private static bool IsDigit(char c) => c is >= '0' and <= '9';
        private static bool IsLower(char c) => c is >= 'a' and <= 'z';
        private static bool IsUpper(char c) => c is >= 'A' and <= 'Z';
        private static bool IsLetter(char c) => IsLower(c) || IsUpper(c);
        private static bool IsWordStart(char c) => !IsDigit(c) && c != '_' && c != '\0';
        private static bool IsWordEnd(char c, char prev) => c == '_' || c == '\0' || (!IsUpper(prev) && IsUpper(c));

        // ---- operators ----

        private SwiftNode? DemangleOperator()
        {
            CheckStack();
            while (true)
            {
                char c = Next();
                switch (c)
                {
                    case 'ÿ': continue; // alignment padding before a symbolic reference
                    case >= '\u0001' and <= '\u000C': return DemangleSymbolicReference(c);
                    case 'A': return DemangleMultiSubstitutions();
                    case 'B': return DemangleBuiltinType();
                    case 'C': return DemangleAnyGenericType(K.Class);
                    case 'D': return DemangleTypeMangling();
                    case 'E': return DemangleExtensionContext();
                    case 'F': return DemanglePlainFunction();
                    case 'G': return DemangleBoundGenericType();
                    case 'H':
                        switch (Next())
                        {
                            case 'A': return DemangleDependentProtocolConformanceAssociated();
                            case 'C': return DemangleConcreteProtocolConformance();
                            case 'D': return DemangleDependentProtocolConformanceRoot();
                            case 'I': return DemangleDependentProtocolConformanceInherited();
                            case 'O': return DemangleDependentProtocolConformanceOpaque();
                            case 'P': return With(K.ProtocolConformanceRefInTypeModule, PopProtocol());
                            case 'p': return With(K.ProtocolConformanceRefInProtocolModule, PopProtocol());
                            case 'X': return DemanglePackProtocolConformance();
                            case 'c': return With(K.ProtocolConformanceDescriptorRecord, PopProtocolConformance());
                            case 'n': return WithPoppedType(K.NominalTypeDescriptorRecord);
                            case 'o': return With(K.OpaqueTypeDescriptorRecord, Pop());
                            case 'r': return With(K.ProtocolDescriptorRecord, PopProtocol());
                            case 'F': return N(K.AccessibleFunctionRecord);
                            default:
                                PushBack();
                                PushBack();
                                return DemangleIdentifier();
                        }
                    case 'I': return DemangleImplFunctionType();
                    case 'K': return N(K.ThrowsAnnotation);
                    case 'L': return DemangleLocalIdentifier();
                    case 'M': return DemangleMetatype();
                    case 'N': return With(K.TypeMetadata, Pop(K.Type));
                    case 'O': return DemangleAnyGenericType(K.Enum);
                    case 'P': return DemangleAnyGenericType(K.Protocol);
                    case 'Q': return DemangleArchetype();
                    case 'R': return DemangleGenericRequirement();
                    case 'S': return DemangleStandardSubstitution();
                    case 'T': return DemangleThunkOrSpecialization();
                    case 'V': return DemangleAnyGenericType(K.Structure);
                    case 'W': return DemangleWitness();
                    case 'X': return DemangleSpecialType();
                    case 'Y': return DemangleTypeAnnotation();
                    case 'Z': return With(K.Static, Pop(IsEntity));
                    case 'a': return DemangleAnyGenericType(K.TypeAlias);
                    case 'c': return PopFunctionType(K.FunctionType);
                    case 'd': return N(K.VariadicMarker);
                    case 'f': return DemangleFunctionEntity();
                    case 'g': return DemangleRetroactiveConformance();
                    case 'h': return CreateType(With(K.Shared, PopTypeAndGetChild()));
                    case 'i': return DemangleSubscript();
                    case 'l': return DemangleGenericSignature(false);
                    case 'm': return CreateType(With(K.Metatype, Pop(K.Type)));
                    case 'n': return CreateType(With(K.Owned, PopTypeAndGetChild()));
                    case 'o': return DemangleOperatorIdentifier();
                    case 'p': return DemangleProtocolListType();
                    case 'q': return CreateType(DemangleGenericParamIndex());
                    case 'r': return DemangleGenericSignature(true);
                    case 's': return N(K.Module, "Swift");
                    case 't': return PopTuple();
                    case 'u': return DemangleGenericType();
                    case 'v': return DemangleVariable();
                    case 'w': return DemangleValueWitness();
                    case 'x': return CreateType(GetDependentGenericParamType(0, 0));
                    case 'y': return N(K.EmptyList);
                    case 'z': return CreateType(With(K.InOut, PopTypeAndGetChild()));
                    case '_': return N(K.FirstElementMarker);
                    case '.':
                        // IRGen's ".<n>" disambiguation suffix
                        PushBack();
                        return N(K.Suffix, ConsumeAll());
                    case '$': return DemangleIntegerType();
                    default:
                        PushBack();
                        return DemangleIdentifier();
                }
            }
        }

        private SwiftNode? DemangleTypeMangling()
        {
            var type = Pop(K.Type);
            var labels = PopFunctionParamLabels(type);
            var mangling = N(K.TypeMangling);
            AddChild(mangling, labels);
            return AddChild(mangling, type);
        }

        private SwiftNode? DemangleSymbolicReference(char raw)
        {
            if (pos + 4 > text.Length) return null;
            int at = pos;
            int value = (byte)text[pos] | (byte)text[pos + 1] << 8 | (byte)text[pos + 2] << 16 | (byte)text[pos + 3] << 24;
            pos += 4;
            (SymbolicReferenceKind kind, bool direct) = raw switch
            {
                '\u0001' => (SymbolicReferenceKind.Context, true),
                '\u0002' => (SymbolicReferenceKind.Context, false),
                '\u0009' => (SymbolicReferenceKind.AccessorFunctionReference, true),
                '\u000A' => (SymbolicReferenceKind.UniqueExtendedExistentialTypeShape, true),
                '\u000B' => (SymbolicReferenceKind.NonUniqueExtendedExistentialTypeShape, true),
                '\u000C' => (SymbolicReferenceKind.ObjectiveCProtocol, true),
                _ => ((SymbolicReferenceKind)(-1), false),
            };
            if ((int)kind < 0) return null;
            var resolved = resolver?.Invoke(kind, direct, value, at);
            if (resolved == null) return null;
            if (kind is SymbolicReferenceKind.Context or SymbolicReferenceKind.ObjectiveCProtocol
                && resolved.Kind is not (K.OpaqueTypeDescriptorSymbolicReference or K.OpaqueReturnTypeOf))
                AddSubstitution(resolved);
            return resolved;
        }

        private SwiftNode? DemangleTypeAnnotation() => Next() switch
        {
            'a' => N(K.AsyncAnnotation),
            'A' => N(K.IsolatedAnyFunctionType),
            'b' => N(K.ConcurrentFunctionType),
            'c' => With(K.GlobalActorFunctionType, PopTypeAndGetChild()),
            'C' => N(K.NonIsolatedCallerFunctionType),
            'i' => CreateType(With(K.Isolated, PopTypeAndGetChild())),
            'j' => DemangleDifferentiableFunctionType(),
            'k' => CreateType(With(K.NoDerivative, PopTypeAndGetChild())),
            'K' => With(K.TypedThrowsAnnotation, PopTypeAndGetChild()),
            't' => CreateType(With(K.CompileTimeLiteral, PopTypeAndGetChild())),
            'g' => CreateType(With(K.ConstValue, PopTypeAndGetChild())),
            'T' => N(K.SendingResultFunctionType),
            'u' => CreateType(With(K.Sending, PopTypeAndGetChild())),
            _ => null,
        };

        private int DemangleNatural()
        {
            if (!IsDigit(Peek())) return -1000;
            ulong num = 0;
            while (true)
            {
                char c = Peek();
                if (!IsDigit(c)) return (int)num;
                num = 10 * num + (ulong)(c - '0');
                if (num > int.MaxValue) return -1000;
                Next();
            }
        }

        private int DemangleIndex()
        {
            if (NextIf('_')) return 0;
            int num = DemangleNatural();
            if (num >= 0 && num < int.MaxValue && NextIf('_')) return num + 1;
            return -1000;
        }

        private SwiftNode? DemangleIndexAsNode()
        {
            int idx = DemangleIndex();
            return idx >= 0 ? N(K.Number, (ulong)idx) : null;
        }

        private SwiftNode? DemangleMultiSubstitutions()
        {
            int repeat = -1;
            while (true)
            {
                char c = Next();
                if (c == '\0') return null;
                if (IsLower(c))
                {
                    var nd = PushMultiSubstitutions(repeat, c - 'a');
                    if (nd == null) return null;
                    Push(nd);
                    repeat = -1;
                    continue;
                }
                if (IsUpper(c)) return PushMultiSubstitutions(repeat, c - 'A');
                if (c == '_')
                {
                    int idx = repeat + 27;
                    return idx >= 0 && idx < subs.Count ? subs[idx] : null;
                }
                PushBack();
                repeat = DemangleNatural();
                if (repeat < 0) return null;
            }
        }

        private SwiftNode? PushMultiSubstitutions(int repeat, int index)
        {
            if (index >= subs.Count || repeat > MaxRepeatCount) return null;
            var nd = subs[index];
            while (repeat-- > 1) Push(nd);
            return nd;
        }

        private SwiftNode? CreateSwiftType(K kind, string name) => CreateType(With(kind, N(K.Module, "Swift"), N(K.Identifier, name)));

        private SwiftNode? DemangleStandardSubstitution()
        {
            switch (Next())
            {
                case 'o': return N(K.Module, "__C");
                case 'C': return N(K.Module, "__C_Synthesized");
                case 'g':
                {
                    var optional = CreateType(With(K.BoundGenericEnum, CreateSwiftType(K.Enum, "Optional"), With(K.TypeList, Pop(K.Type))));
                    AddSubstitution(optional);
                    return optional;
                }
                default:
                {
                    PushBack();
                    int repeat = DemangleNatural();
                    if (repeat > MaxRepeatCount) return null;
                    bool second = NextIf('c');
                    if (CreateStandardSubstitution(Next(), second) is not { } nd) return null;
                    while (repeat-- > 1) Push(nd);
                    return nd;
                }
            }
        }

        private SwiftNode? CreateStandardSubstitution(char c, bool second)
        {
            if (!second)
                return c switch
                {
                    'A' => CreateSwiftType(K.Structure, "AutoreleasingUnsafeMutablePointer"),
                    'a' => CreateSwiftType(K.Structure, "Array"),
                    'b' => CreateSwiftType(K.Structure, "Bool"),
                    'D' => CreateSwiftType(K.Structure, "Dictionary"),
                    'd' => CreateSwiftType(K.Structure, "Double"),
                    'f' => CreateSwiftType(K.Structure, "Float"),
                    'h' => CreateSwiftType(K.Structure, "Set"),
                    'I' => CreateSwiftType(K.Structure, "DefaultIndices"),
                    'i' => CreateSwiftType(K.Structure, "Int"),
                    'J' => CreateSwiftType(K.Structure, "Character"),
                    'N' => CreateSwiftType(K.Structure, "ClosedRange"),
                    'n' => CreateSwiftType(K.Structure, "Range"),
                    'O' => CreateSwiftType(K.Structure, "ObjectIdentifier"),
                    'P' => CreateSwiftType(K.Structure, "UnsafePointer"),
                    'p' => CreateSwiftType(K.Structure, "UnsafeMutablePointer"),
                    'R' => CreateSwiftType(K.Structure, "UnsafeBufferPointer"),
                    'r' => CreateSwiftType(K.Structure, "UnsafeMutableBufferPointer"),
                    'S' => CreateSwiftType(K.Structure, "String"),
                    's' => CreateSwiftType(K.Structure, "Substring"),
                    'u' => CreateSwiftType(K.Structure, "UInt"),
                    'V' => CreateSwiftType(K.Structure, "UnsafeRawPointer"),
                    'v' => CreateSwiftType(K.Structure, "UnsafeMutableRawPointer"),
                    'W' => CreateSwiftType(K.Structure, "UnsafeRawBufferPointer"),
                    'w' => CreateSwiftType(K.Structure, "UnsafeMutableRawBufferPointer"),
                    'q' => CreateSwiftType(K.Enum, "Optional"),
                    'B' => CreateSwiftType(K.Protocol, "BinaryFloatingPoint"),
                    'E' => CreateSwiftType(K.Protocol, "Encodable"),
                    'e' => CreateSwiftType(K.Protocol, "Decodable"),
                    'F' => CreateSwiftType(K.Protocol, "FloatingPoint"),
                    'G' => CreateSwiftType(K.Protocol, "RandomNumberGenerator"),
                    'H' => CreateSwiftType(K.Protocol, "Hashable"),
                    'j' => CreateSwiftType(K.Protocol, "Numeric"),
                    'K' => CreateSwiftType(K.Protocol, "BidirectionalCollection"),
                    'k' => CreateSwiftType(K.Protocol, "RandomAccessCollection"),
                    'L' => CreateSwiftType(K.Protocol, "Comparable"),
                    'l' => CreateSwiftType(K.Protocol, "Collection"),
                    'M' => CreateSwiftType(K.Protocol, "MutableCollection"),
                    'm' => CreateSwiftType(K.Protocol, "RangeReplaceableCollection"),
                    'Q' => CreateSwiftType(K.Protocol, "Equatable"),
                    'T' => CreateSwiftType(K.Protocol, "Sequence"),
                    't' => CreateSwiftType(K.Protocol, "IteratorProtocol"),
                    'U' => CreateSwiftType(K.Protocol, "UnsignedInteger"),
                    'X' => CreateSwiftType(K.Protocol, "RangeExpression"),
                    'x' => CreateSwiftType(K.Protocol, "Strideable"),
                    'Y' => CreateSwiftType(K.Protocol, "RawRepresentable"),
                    'y' => CreateSwiftType(K.Protocol, "StringProtocol"),
                    'Z' => CreateSwiftType(K.Protocol, "SignedInteger"),
                    'z' => CreateSwiftType(K.Protocol, "BinaryInteger"),
                    _ => null,
                };
            return c switch
            {
                'A' => CreateSwiftType(K.Protocol, "Actor"),
                'C' => CreateSwiftType(K.Structure, "CheckedContinuation"),
                'c' => CreateSwiftType(K.Structure, "UnsafeContinuation"),
                'E' => CreateSwiftType(K.Structure, "CancellationError"),
                'e' => CreateSwiftType(K.Structure, "UnownedSerialExecutor"),
                'F' => CreateSwiftType(K.Protocol, "Executor"),
                'f' => CreateSwiftType(K.Protocol, "SerialExecutor"),
                'G' => CreateSwiftType(K.Structure, "TaskGroup"),
                'g' => CreateSwiftType(K.Structure, "ThrowingTaskGroup"),
                'h' => CreateSwiftType(K.Protocol, "TaskExecutor"),
                'I' => CreateSwiftType(K.Protocol, "AsyncIteratorProtocol"),
                'i' => CreateSwiftType(K.Protocol, "AsyncSequence"),
                'J' => CreateSwiftType(K.Structure, "UnownedJob"),
                'M' => CreateSwiftType(K.Class, "MainActor"),
                'P' => CreateSwiftType(K.Structure, "TaskPriority"),
                'S' => CreateSwiftType(K.Structure, "AsyncStream"),
                's' => CreateSwiftType(K.Structure, "AsyncThrowingStream"),
                'T' => CreateSwiftType(K.Structure, "Task"),
                't' => CreateSwiftType(K.Structure, "UnsafeCurrentTask"),
                _ => null,
            };
        }

        private SwiftNode? DemangleIdentifier()
        {
            bool hasWordSubsts = false, punycoded = false;
            char c = Peek();
            if (!IsDigit(c)) return null;
            if (c == '0')
            {
                Next();
                if (Peek() == '0')
                {
                    Next();
                    punycoded = true;
                }
                else hasWordSubsts = true;
            }
            var ident = new StringBuilder();
            do
            {
                while (hasWordSubsts && IsLetter(Peek()))
                {
                    char w = Next();
                    int wordIdx;
                    if (IsLower(w)) wordIdx = w - 'a';
                    else
                    {
                        wordIdx = w - 'A';
                        hasWordSubsts = false;
                    }
                    if (wordIdx >= numWords) return null;
                    ident.Append(words[wordIdx]);
                    if (ident.Length > MaxIdentifierLength) return null;
                }
                if (NextIf('0')) break;
                int numChars = DemangleNatural();
                if (numChars <= 0) return null;
                if (punycoded) NextIf('_');
                if (pos + numChars > text.Length) return null;
                var slice = text.Substring(pos, numChars);
                if (punycoded)
                {
                    if (Punycode.Decode(slice) is not { } decoded) return null;
                    ident.Append(decoded);
                }
                else
                {
                    ident.Append(slice);
                    int wordStart = -1;
                    for (int i = 0; i <= slice.Length; i++)
                    {
                        char ch = i < slice.Length ? slice[i] : '\0';
                        if (wordStart >= 0 && IsWordEnd(ch, slice[i - 1]))
                        {
                            if (i - wordStart >= 2 && numWords < MaxNumWords) words[numWords++] = slice[wordStart..i];
                            wordStart = -1;
                        }
                        if (wordStart < 0 && IsWordStart(ch)) wordStart = i;
                    }
                }
                if (ident.Length > MaxIdentifierLength) return null;
                pos += numChars;
            } while (hasWordSubsts);
            if (ident.Length == 0) return null;
            var node = N(K.Identifier, ident.ToString());
            AddSubstitution(node);
            return node;
        }

        private const string OperatorChars = "& @/= >    <*!|+?%-~   ^ .";

        private SwiftNode? DemangleOperatorIdentifier()
        {
            var ident = Pop(K.Identifier);
            if (ident == null) return null;
            var op = new StringBuilder();
            foreach (char c in ident.Text!)
            {
                if (c >= 0x80)
                {
                    op.Append(c);
                    continue;
                }
                if (!IsLower(c)) return null;
                char o = OperatorChars[c - 'a'];
                if (o == ' ') return null;
                op.Append(o);
            }
            return Next() switch
            {
                'i' => N(K.InfixOperator, op.ToString()),
                'p' => N(K.PrefixOperator, op.ToString()),
                'P' => N(K.PostfixOperator, op.ToString()),
                _ => null,
            };
        }

        private SwiftNode? DemangleLocalIdentifier()
        {
            if (NextIf('L'))
            {
                var discriminator = Pop(K.Identifier);
                var name = Pop(IsDeclName);
                return With(K.PrivateDeclName, discriminator, name);
            }
            if (NextIf('l')) return With(K.PrivateDeclName, Pop(K.Identifier));
            char p = Peek();
            if (p is >= 'a' and <= 'j' or >= 'A' and <= 'J')
            {
                char related = Next();
                var kindNode = N(K.Identifier, related.ToString());
                var name = Pop();
                var result = N(K.RelatedEntityDeclName);
                AddChild(result, kindNode);
                return AddChild(result, name);
            }
            var disc = DemangleIndexAsNode();
            return With(K.LocalDeclName, disc, Pop(IsDeclName));
        }

        private SwiftNode? PopModule()
        {
            if (Pop(K.Identifier) is { } ident) return ChangeKind(ident, K.Module);
            return Pop(K.Module);
        }

        private SwiftNode? PopContext()
        {
            if (PopModule() is { } mod) return mod;
            if (Pop(K.Type) is { } ty)
            {
                if (ty.Count != 1) return null;
                var child = ty.First!;
                return IsContext(child.Kind) ? child : null;
            }
            return Pop(IsContext);
        }

        private SwiftNode? PopTypeAndGetChild()
        {
            var ty = Pop(K.Type);
            return ty == null || ty.Count != 1 ? null : ty.First;
        }

        private SwiftNode? PopTypeAndGetAnyGeneric() => PopTypeAndGetChild() is { } c && IsAnyGeneric(c.Kind) ? c : null;

        private SwiftNode? DemangleBuiltinType()
        {
            const int maxTypeSize = 4096;
            SwiftNode? ty;
            switch (Next())
            {
                case 'A': ty = N(K.BuiltinTypeName, "Builtin.ImplicitActor"); break;
                case 'b': ty = N(K.BuiltinTypeName, "Builtin.BridgeObject"); break;
                case 'B': ty = N(K.BuiltinTypeName, "Builtin.UnsafeValueBuffer"); break;
                case 'e': ty = N(K.BuiltinTypeName, "Builtin.Executor"); break;
                case 'f':
                {
                    int size = DemangleIndex() - 1;
                    if (size is <= 0 or > maxTypeSize) return null;
                    ty = N(K.BuiltinTypeName, "Builtin.FPIEEE" + size);
                    break;
                }
                case 'i':
                {
                    int size = DemangleIndex() - 1;
                    if (size is <= 0 or > maxTypeSize) return null;
                    ty = N(K.BuiltinTypeName, "Builtin.Int" + size);
                    break;
                }
                case 'I': ty = N(K.BuiltinTypeName, "Builtin.IntLiteral"); break;
                case 'v':
                {
                    int elts = DemangleIndex() - 1;
                    if (elts is <= 0 or > maxTypeSize) return null;
                    var elt = PopTypeAndGetChild();
                    if (elt == null || elt.Kind != K.BuiltinTypeName || !elt.Text!.StartsWith("Builtin.", StringComparison.Ordinal)) return null;
                    ty = N(K.BuiltinTypeName, "Builtin.Vec" + elts + "x" + elt.Text["Builtin.".Length..]);
                    break;
                }
                case 'V':
                {
                    var element = Pop(K.Type);
                    if (element == null) return null;
                    var size = Pop(K.Type);
                    if (size == null) return null;
                    ty = N(K.BuiltinFixedArray);
                    ty.Add(size);
                    ty.Add(element);
                    break;
                }
                case 'W':
                {
                    var referent = Pop(K.Type);
                    if (referent == null) return null;
                    ty = N(K.BuiltinBorrow);
                    ty.Add(referent);
                    break;
                }
                case 'O': ty = N(K.BuiltinTypeName, "Builtin.UnknownObject"); break;
                case 'o': ty = N(K.BuiltinTypeName, "Builtin.NativeObject"); break;
                case 'p': ty = N(K.BuiltinTypeName, "Builtin.RawPointer"); break;
                case 'j': ty = N(K.BuiltinTypeName, "Builtin.Job"); break;
                case 'D': ty = N(K.BuiltinTypeName, "Builtin.DefaultActorStorage"); break;
                case 'd': ty = N(K.BuiltinTypeName, "Builtin.NonDefaultDistributedActorStorage"); break;
                case 'c': ty = N(K.BuiltinTypeName, "Builtin.RawUnsafeContinuation"); break;
                case 't': ty = N(K.BuiltinTypeName, "Builtin.SILToken"); break;
                case 'w': ty = N(K.BuiltinTypeName, "Builtin.Word"); break;
                case 'P': ty = N(K.BuiltinTypeName, "Builtin.PackIndex"); break;
                case 'T': ty = N(K.BuiltinTupleType); break;
                default: return null;
            }
            return CreateType(ty);
        }

        private SwiftNode? DemangleAnyGenericType(K kind)
        {
            var name = Pop(IsDeclName);
            var ctx = PopContext();
            var ty = CreateType(With(kind, ctx, name));
            AddSubstitution(ty);
            return ty;
        }

        private SwiftNode? DemangleExtensionContext()
        {
            var sig = Pop(K.DependentGenericSignature);
            var module = PopModule();
            var type = PopTypeAndGetAnyGeneric();
            var ext = With(K.Extension, module, type);
            if (sig != null) ext = AddChild(ext, sig);
            return ext;
        }

        /// <summary>Marks opaque return types under <paramref name="visited"/> as belonging to the declaration (not printed).</summary>
        private SwiftNode? SetParentForOpaqueReturnTypeNodes(SwiftNode? parent, SwiftNode? visited)
        {
            if (parent == null || visited == null) return null;
            void Visit(SwiftNode n)
            {
                CheckStack();
                if (n.Kind == K.OpaqueReturnType)
                {
                    if (n.HasChildren && n.Last!.Kind == K.OpaqueReturnTypeParent) return;
                    n.Add(N(K.OpaqueReturnTypeParent, ""));
                    return;
                }
                if (n.Kind is K.Function or K.Variable or K.Subscript) return;
                foreach (var c in n.Children) Visit(c);
            }
            Visit(visited);
            return parent;
        }

        private SwiftNode? DemanglePlainFunction()
        {
            var sig = Pop(K.DependentGenericSignature);
            var type = PopFunctionType(K.FunctionType);
            var labels = PopFunctionParamLabels(type);
            if (sig != null) type = CreateType(With(K.DependentGenericType, sig, type));
            var name = Pop(IsDeclName);
            var ctx = PopContext();
            var result = labels != null ? With(K.Function, ctx, name, labels, type) : With(K.Function, ctx, name, type);
            return SetParentForOpaqueReturnTypeNodes(result, type);
        }

        private SwiftNode? PopFunctionType(K kind, bool hasClangType = false)
        {
            SwiftNode? fn = N(kind);
            if (hasClangType) AddChild(fn, DemangleClangType());
            AddChild(fn, Pop(K.SendingResultFunctionType));
            AddChild(fn, Pop(k => k is K.GlobalActorFunctionType or K.IsolatedAnyFunctionType or K.NonIsolatedCallerFunctionType));
            AddChild(fn, Pop(K.DifferentiableFunctionType));
            AddChild(fn, Pop(k => k is K.ThrowsAnnotation or K.TypedThrowsAnnotation));
            AddChild(fn, Pop(K.ConcurrentFunctionType));
            AddChild(fn, Pop(K.AsyncAnnotation));
            fn = AddChild(fn, PopFunctionParams(K.ArgumentTuple));
            AddChild(fn, Pop(K.YieldTypes));
            fn = AddChild(fn, PopFunctionParams(K.ReturnType));
            return CreateType(fn);
        }

        private SwiftNode? PopFunctionParams(K kind)
        {
            var paramsType = Pop(K.EmptyList) != null ? CreateType(N(K.Tuple)) : Pop(K.Type);
            return With(kind, paramsType);
        }

        private SwiftNode? PopFunctionParamLabels(SwiftNode? type)
        {
            if (!oldFunctionTypeMangling && Pop(K.EmptyList) != null) return N(K.LabelList);
            if (type == null || type.Kind != K.Type) return null;
            var fn = type.First!;
            if (fn.Kind == K.DependentGenericType) fn = fn[1]!.First!;
            if (fn.Kind is not (K.FunctionType or K.NoEscapeFunctionType or K.CalledOnceFunctionType or K.CalledAtMostOnceFunctionType)) return null;

            int first = 0;
            if (fn[first]!.Kind == K.SendingResultFunctionType) first++;
            if (fn[first]!.Kind == K.GlobalActorFunctionType) first++;
            if (fn[first]!.Kind == K.IsolatedAnyFunctionType) first++;
            if (fn[first]!.Kind == K.NonIsolatedCallerFunctionType) first++;
            if (fn[first]!.Kind == K.DifferentiableFunctionType) first++;
            if (fn[first]!.Kind is K.ThrowsAnnotation or K.TypedThrowsAnnotation) first++;
            if (fn[first]!.Kind == K.ConcurrentFunctionType) first++;
            if (fn[first]!.Kind == K.AsyncAnnotation) first++;
            var parameterType = fn[first]!;
            if (parameterType.Kind != K.ArgumentTuple) return null;
            var paramsType = parameterType.First!;
            var parameters = paramsType.First!;
            int numParams = parameters.Kind == K.Tuple ? parameters.Count : 1;
            if (numParams == 0) return null;

            var labels = N(K.LabelList);
            var tuple = parameterType.First!.First;
            if (oldFunctionTypeMangling && (tuple == null || tuple.Kind != K.Tuple)) return labels;

            bool hasLabels = false;
            for (int i = 0; i < numParams; i++)
            {
                SwiftNode? label;
                if (oldFunctionTypeMangling)
                {
                    var param = tuple![i]!;
                    int at = -1;
                    for (int j = 0; j < param.Count; j++)
                        if (param[j]!.Kind == K.TupleElementName)
                        {
                            at = j;
                            break;
                        }
                    if (at >= 0)
                    {
                        var name = param[at]!;
                        param.RemoveAt(at);
                        label = N(K.Identifier, name.Text!);
                    }
                    else label = N(K.FirstElementMarker);
                }
                else label = Pop();
                if (label == null || label.Kind is not (K.Identifier or K.FirstElementMarker)) return null;
                labels.Add(label);
                hasLabels |= label.Kind != K.FirstElementMarker;
            }
            if (!hasLabels) return N(K.LabelList);
            if (!oldFunctionTypeMangling) labels.Reverse();
            return labels;
        }

        private SwiftNode? PopTuple()
        {
            var root = N(K.Tuple);
            if (Pop(K.EmptyList) == null)
            {
                bool first;
                do
                {
                    first = Pop(K.FirstElementMarker) != null;
                    var elt = N(K.TupleElement);
                    AddChild(elt, Pop(K.VariadicMarker));
                    if (Pop(K.Identifier) is { } ident) elt.Add(N(K.TupleElementName, ident.Text!));
                    var ty = Pop(K.Type);
                    if (ty == null) return null;
                    elt.Add(ty);
                    root.Add(elt);
                } while (!first);
                root.Reverse();
            }
            return CreateType(root);
        }

        private SwiftNode? PopTypeSequence(SwiftNode root)
        {
            if (Pop(K.EmptyList) == null)
            {
                bool first;
                do
                {
                    first = Pop(K.FirstElementMarker) != null;
                    var ty = Pop(K.Type);
                    if (ty == null) return null;
                    root.Add(ty);
                } while (!first);
                root.Reverse();
            }
            return root;
        }

        private SwiftNode? PopPack() => CreateType(PopTypeSequence(N(K.Pack)));

        private SwiftNode? PopSILPack()
        {
            var root = Next() switch { 'd' => N(K.SILPackDirect), 'i' => N(K.SILPackIndirect), _ => null };
            return root == null ? null : CreateType(PopTypeSequence(root));
        }

        private SwiftNode? PopTypeList() => PopTypeSequence(N(K.TypeList));

        private SwiftNode? PopProtocol()
        {
            if (Pop(K.Type) is { } type)
            {
                if (type.Count < 1 || !IsProtocolNode(type)) return null;
                return type;
            }
            if (Pop(K.ProtocolSymbolicReference) is { } sym) return sym;
            if (Pop(K.ObjectiveCProtocolSymbolicReference) is { } objc) return objc;
            var name = Pop(IsDeclName);
            var ctx = PopContext();
            return CreateType(With(K.Protocol, ctx, name));
        }

        private SwiftNode? PopAnyProtocolConformanceList()
        {
            var list = N(K.AnyProtocolConformanceList);
            if (Pop(K.EmptyList) == null)
            {
                bool first;
                do
                {
                    first = Pop(K.FirstElementMarker) != null;
                    var conformance = PopAnyProtocolConformance();
                    if (conformance == null) return null;
                    list.Add(conformance);
                } while (!first);
                list.Reverse();
            }
            return list;
        }

        private SwiftNode? PopAnyProtocolConformance() => Pop(k => k is K.ConcreteProtocolConformance or K.PackProtocolConformance
            or K.DependentProtocolConformanceRoot or K.DependentProtocolConformanceInherited or K.DependentProtocolConformanceAssociated
            or K.DependentProtocolConformanceOpaque);

        private SwiftNode? DemangleRetroactiveProtocolConformanceRef()
        {
            var module = PopModule();
            var proto = PopProtocol();
            return With(K.ProtocolConformanceRefInOtherModule, proto, module);
        }

        private SwiftNode? DemangleConcreteProtocolConformance()
        {
            var conditional = PopAnyProtocolConformanceList();
            var reference = Pop(K.ProtocolConformanceRefInTypeModule) ?? Pop(K.ProtocolConformanceRefInProtocolModule)
                            ?? DemangleRetroactiveProtocolConformanceRef();
            var type = Pop(K.Type);
            return With(K.ConcreteProtocolConformance, type, reference, conditional);
        }

        private SwiftNode? DemanglePackProtocolConformance() => With(K.PackProtocolConformance, PopAnyProtocolConformanceList());

        private SwiftNode? PopDependentProtocolConformance() => Pop(k => k is K.DependentProtocolConformanceRoot or K.DependentProtocolConformanceInherited
            or K.DependentProtocolConformanceAssociated);

        private SwiftNode? DemangleDependentProtocolConformanceRoot()
        {
            var index = DemangleDependentConformanceIndex();
            var protocol = PopProtocol();
            var dependent = Pop(K.Type);
            return With(K.DependentProtocolConformanceRoot, dependent, protocol, index);
        }

        private SwiftNode? DemangleDependentProtocolConformanceInherited()
        {
            var index = DemangleDependentConformanceIndex();
            var protocol = PopProtocol();
            var nested = PopDependentProtocolConformance();
            return With(K.DependentProtocolConformanceInherited, nested, protocol, index);
        }

        private SwiftNode? PopDependentAssociatedConformance()
        {
            var protocol = PopProtocol();
            var dependent = Pop(K.Type);
            return With(K.DependentAssociatedConformance, dependent, protocol);
        }

        private SwiftNode? DemangleDependentProtocolConformanceAssociated()
        {
            var index = DemangleDependentConformanceIndex();
            var associated = PopDependentAssociatedConformance();
            var nested = PopDependentProtocolConformance();
            return With(K.DependentProtocolConformanceAssociated, nested, associated, index);
        }

        private SwiftNode? DemangleDependentConformanceIndex()
        {
            int index = DemangleIndex();
            if (index <= 0) return null;
            if (index == 1) return N(K.UnknownIndex);
            return N(K.Index, (ulong)(index - 2));
        }

        private SwiftNode? DemangleDependentProtocolConformanceOpaque()
        {
            var type = Pop(K.Type);
            var conformance = PopDependentProtocolConformance();
            return With(K.DependentProtocolConformanceOpaque, conformance, type);
        }

        private SwiftNode? DemangleRetroactiveConformance()
        {
            var index = DemangleIndexAsNode();
            var conformance = PopAnyProtocolConformance();
            return With(K.RetroactiveConformance, index, conformance);
        }

        private SwiftNode? PopRetroactiveConformances()
        {
            SwiftNode? list = null;
            while (Pop(K.RetroactiveConformance) is { } c)
            {
                list ??= N(K.TypeList);
                list.Add(c);
            }
            list?.Reverse();
            return list;
        }

        private bool DemangleBoundGenerics(List<SwiftNode> typeLists, out SwiftNode? retroactive)
        {
            retroactive = PopRetroactiveConformances();
            while (true)
            {
                var list = N(K.TypeList);
                typeLists.Add(list);
                while (Pop(K.Type) is { } ty) list.Add(ty);
                list.Reverse();
                if (Pop(K.EmptyList) != null) break;
                if (Pop(K.FirstElementMarker) == null) return false;
            }
            return true;
        }

        private SwiftNode? DemangleBoundGenericType()
        {
            var lists = new List<SwiftNode>(4);
            if (!DemangleBoundGenerics(lists, out var retroactive)) return null;
            var nominal = PopTypeAndGetAnyGeneric();
            if (nominal == null) return null;
            var bound = DemangleBoundGenericArgs(nominal, lists, 0);
            if (bound == null) return null;
            AddChild(bound, retroactive);
            var ty = CreateType(bound);
            AddSubstitution(ty);
            return ty;
        }

        private static bool ConsumesGenericArgs(SwiftNode n) => n.Kind is not (K.Variable or K.Subscript or K.ImplicitClosure or K.ExplicitClosure
            or K.DefaultArgumentInitializer or K.Initializer or K.PropertyWrapperBackingInitializer or K.PropertyWrappedFieldInitAccessor
            or K.PropertyWrapperInitFromProjectedValue or K.Static);

        private SwiftNode? DemangleBoundGenericArgs(SwiftNode? nominal, List<SwiftNode> lists, int listIdx)
        {
            CheckStack();
            if (nominal == null || listIdx >= lists.Count) return null;
            if (nominal.Kind is K.TypeSymbolicReference or K.ProtocolSymbolicReference)
            {
                var remaining = N(K.TypeList);
                for (int i = lists.Count - 1; i >= listIdx; i--)
                    foreach (var c in lists[i].Children) remaining.Add(c);
                return With(K.BoundGenericOtherNominalType, CreateType(nominal), remaining);
            }
            if (nominal.Count == 0) return null;
            var context = nominal.First!;
            bool consumes = ConsumesGenericArgs(nominal);
            var args = lists[listIdx];
            if (consumes) listIdx++;
            if (listIdx < lists.Count)
            {
                SwiftNode? boundParent;
                if (context.Kind == K.Extension)
                {
                    boundParent = DemangleBoundGenericArgs(context[1], lists, listIdx);
                    boundParent = With(K.Extension, context.First, boundParent);
                    if (context.Count == 3) AddChild(boundParent, context[2]);
                }
                else boundParent = DemangleBoundGenericArgs(context, lists, listIdx);
                var renewed = With(nominal.Kind, boundParent);
                if (renewed == null) return null;
                for (int i = 1; i < nominal.Count; i++) AddChild(renewed, nominal[i]);
                nominal = renewed;
            }
            if (!consumes || args.Count == 0) return nominal;
            K kind;
            switch (nominal.Kind)
            {
                case K.Class: kind = K.BoundGenericClass; break;
                case K.Structure: kind = K.BoundGenericStructure; break;
                case K.Enum: kind = K.BoundGenericEnum; break;
                case K.Protocol: kind = K.BoundGenericProtocol; break;
                case K.OtherNominalType: kind = K.BoundGenericOtherNominalType; break;
                case K.TypeAlias: kind = K.BoundGenericTypeAlias; break;
                case K.Function or K.Constructor: return With(K.BoundGenericFunction, nominal, args);
                default: return null;
            }
            return With(kind, CreateType(nominal), args);
        }

        private SwiftNode? DemangleImplParamConvention(K kind)
        {
            string? attr = Next() switch
            {
                'i' => "@in",
                'c' => "@in_constant",
                'l' => "@inout",
                'b' => "@inout_aliasable",
                'n' => "@in_guaranteed",
                'X' => "@in_cxx",
                'x' => "@owned",
                'g' => "@guaranteed",
                'e' => "@deallocating",
                'y' => "@unowned",
                'v' => "@pack_owned",
                'p' => "@pack_guaranteed",
                'm' => "@pack_inout",
                _ => null,
            };
            if (attr == null)
            {
                PushBack();
                return null;
            }
            return With(kind, N(K.ImplConvention, attr));
        }

        private SwiftNode? DemangleImplResultConvention(K kind)
        {
            string? attr = Next() switch
            {
                'r' => "@out",
                'o' => "@owned",
                'd' => "@unowned",
                'u' => "@unowned_inner_pointer",
                'a' => "@autoreleased",
                'k' => "@pack_out",
                'l' => "@guaranteed_address",
                'g' => "@guaranteed",
                'm' => "@inout",
                _ => null,
            };
            if (attr == null)
            {
                PushBack();
                return null;
            }
            return With(kind, N(K.ImplConvention, attr));
        }

        private SwiftNode? DemangleClangType()
        {
            int numChars = DemangleNatural();
            if (numChars <= 0 || pos + numChars > text.Length) return null;
            var s = text.Substring(pos, numChars);
            pos += numChars;
            return N(K.ClangType, s);
        }

        private SwiftNode? DemangleImplFunctionType()
        {
            SwiftNode? type = N(K.ImplFunctionType);
            if (NextIf('s'))
            {
                var lists = new List<SwiftNode>();
                if (!DemangleBoundGenerics(lists, out var retro)) return null;
                var sig = Pop(K.DependentGenericSignature);
                if (sig == null) return null;
                var subsNode = N(K.ImplPatternSubstitutions);
                subsNode.Add(sig);
                subsNode.Add(lists[0]);
                if (retro != null) subsNode.Add(retro);
                type.Add(subsNode);
            }
            if (NextIf('I'))
            {
                var lists = new List<SwiftNode>();
                if (!DemangleBoundGenerics(lists, out var retro)) return null;
                if (lists.Count != 1) return null;
                var subsNode = N(K.ImplInvocationSubstitutions);
                subsNode.Add(lists[0]);
                if (retro != null) subsNode.Add(retro);
                type.Add(subsNode);
            }
            var genSig = Pop(K.DependentGenericSignature);
            if (genSig != null && NextIf('P')) genSig = ChangeKind(genSig, K.DependentPseudogenericSignature);
            if (NextIf('e')) type.Add(N(K.ImplEscaping));
            if (NextIf('A')) type.Add(N(K.ImplErasedIsolation));
            if (NextIf('N')) type.Add(N(K.ImplNonisolatedNonsendingIsolation));
            if (NextIf('O')) type.Add(NextIf('o') ? N(K.ImplCalledAtMostOnceFunction) : N(K.ImplCalledOnceFunction));
            if (Peek() is 'd' or 'l' or 'f' or 'r') type.Add(N(K.ImplDifferentiabilityKind, Next()));

            string? callee = Next() switch
            {
                'y' => "@callee_unowned",
                'g' => "@callee_guaranteed",
                'x' => "@callee_owned",
                't' => "@convention(thin)",
                _ => null,
            };
            if (callee == null) return null;
            type.Add(N(K.ImplConvention, callee));

            string? conv = null;
            bool hasClangType = false;
            switch (Next())
            {
                case 'B': conv = "block"; break;
                case 'C': conv = "c"; break;
                case 'z':
                    switch (Next())
                    {
                        case 'B': hasClangType = true; conv = "block"; break;
                        case 'C': hasClangType = true; conv = "c"; break;
                        default: PushBack(); PushBack(); break;
                    }
                    break;
                case 'M': conv = "method"; break;
                case 'O': conv = "objc_method"; break;
                case 'K': conv = "closure"; break;
                case 'W': conv = "witness_method"; break;
                case 'V': conv = "com_method"; break;
                default: PushBack(); break;
            }
            if (conv != null)
            {
                var attr = N(K.ImplFunctionConvention);
                attr.Add(N(K.ImplFunctionConventionName, conv));
                if (hasClangType) AddChild(attr, DemangleClangType());
                type.Add(attr);
            }
            string? coro = NextIf('A') ? "yield_once" : NextIf('I') ? "yield_once_2" : NextIf('G') ? "yield_many" : null;
            if (coro != null) type.Add(N(K.ImplCoroutineKind, coro));
            if (NextIf('h')) type.Add(N(K.ImplFunctionAttribute, "@Sendable"));
            if (NextIf('H')) type.Add(N(K.ImplFunctionAttribute, "@async"));
            if (NextIf('T')) type.Add(N(K.ImplSendingResult));
            AddChild(type, genSig);

            int numTypes = 0;
            while (DemangleImplParamConvention(K.ImplParameter) is { } param)
            {
                type = AddChild(type, param);
                SwiftNode? p = param;
                p = AddChild(p, N(K.ImplParameterResultDifferentiability, NextIf('w') ? "@noDerivative" : ""));
                if (NextIf('T')) p = AddChild(p, N(K.ImplParameterSending, "sending"));
                if (NextIf('I')) p = AddChild(p, N(K.ImplParameterIsolated, "isolated"));
                if (NextIf('L')) AddChild(p, N(K.ImplParameterImplicitLeading, "sil_implicit_leading_param"));
                numTypes++;
            }
            while (DemangleImplResultConvention(K.ImplResult) is { } result)
            {
                type = AddChild(type, result);
                AddChild(result, N(K.ImplParameterResultDifferentiability, NextIf('w') ? "@noDerivative" : ""));
                numTypes++;
            }
            while (NextIf('Y'))
            {
                var yield = DemangleImplParamConvention(K.ImplYield);
                if (yield == null) return null;
                type = AddChild(type, yield);
                numTypes++;
            }
            if (NextIf('z'))
            {
                var error = DemangleImplResultConvention(K.ImplErrorResult);
                if (error == null) return null;
                type = AddChild(type, error);
                numTypes++;
            }
            if (!NextIf('_') || type == null) return null;
            for (int i = 0; i < numTypes; i++)
            {
                var ty = Pop(K.Type);
                if (ty == null) return null;
                type[type.Count - i - 1]!.Add(ty);
            }
            return CreateType(type);
        }

        private SwiftNode? DemangleMetatype()
        {
            switch (Next())
            {
                case 'a': return WithPoppedType(K.TypeMetadataAccessFunction);
                case 'A': return With(K.ReflectionMetadataAssocTypeDescriptor, PopProtocolConformance());
                case 'b': return WithPoppedType(K.CanonicalSpecializedGenericTypeMetadataAccessFunction);
                case 'B': return With(K.ReflectionMetadataBuiltinDescriptor, Pop(K.Type));
                case 'c': return With(K.ProtocolConformanceDescriptor, PopProtocolConformance());
                case 'C':
                {
                    var ty = Pop(K.Type);
                    if (ty == null || !IsAnyGeneric(ty.First!.Kind)) return null;
                    return With(K.ReflectionMetadataSuperclassDescriptor, ty.First);
                }
                case 'D': return WithPoppedType(K.TypeMetadataDemanglingCache);
                case 'f': return WithPoppedType(K.FullTypeMetadata);
                case 'F': return With(K.ReflectionMetadataFieldDescriptor, Pop(K.Type));
                case 'g': return With(K.OpaqueTypeDescriptorAccessor, Pop());
                case 'h': return With(K.OpaqueTypeDescriptorAccessorImpl, Pop());
                case 'i': return WithPoppedType(K.TypeMetadataInstantiationFunction);
                case 'I': return WithPoppedType(K.TypeMetadataInstantiationCache);
                case 'j': return With(K.OpaqueTypeDescriptorAccessorKey, Pop());
                case 'J': return With(K.NoncanonicalSpecializedGenericTypeMetadataCache, Pop());
                case 'k': return With(K.OpaqueTypeDescriptorAccessorVar, Pop());
                case 'K': return With(K.MetadataInstantiationCache, Pop());
                case 'l': return WithPoppedType(K.TypeMetadataSingletonInitializationCache);
                case 'L': return WithPoppedType(K.TypeMetadataLazyCache);
                case 'm': return WithPoppedType(K.Metaclass);
                case 'M': return WithPoppedType(K.CanonicalSpecializedGenericMetaclass);
                case 'n': return WithPoppedType(K.NominalTypeDescriptor);
                case 'N': return WithPoppedType(K.NoncanonicalSpecializedGenericTypeMetadata);
                case 'o': return WithPoppedType(K.ClassMetadataBaseOffset);
                case 'p': return With(K.ProtocolDescriptor, PopProtocol());
                case 'P': return WithPoppedType(K.GenericTypeMetadataPattern);
                case 'q': return With(K.Uniquable, Pop());
                case 'Q': return With(K.OpaqueTypeDescriptor, Pop());
                case 'r': return WithPoppedType(K.TypeMetadataCompletionFunction);
                case 's': return WithPoppedType(K.ObjCResilientClassStub);
                case 'S': return With(K.ProtocolSelfConformanceDescriptor, PopProtocol());
                case 't': return WithPoppedType(K.FullObjCResilientClassStub);
                case 'u': return WithPoppedType(K.MethodLookupFunction);
                case 'U': return WithPoppedType(K.ObjCMetadataUpdateFunction);
                case 'V': return With(K.PropertyDescriptor, Pop(IsEntity));
                case 'X': return DemanglePrivateContextDescriptor();
                case 'z': return WithPoppedType(K.CanonicalPrespecializedGenericTypeCachingOnceToken);
                default: return null;
            }
        }

        private SwiftNode? DemanglePrivateContextDescriptor()
        {
            switch (Next())
            {
                case 'E': return PopContext() is { } ext ? With(K.ExtensionDescriptor, ext) : null;
                case 'M': return PopModule() is { } module ? With(K.ModuleDescriptor, module) : null;
                case 'Y':
                {
                    var discriminator = Pop();
                    if (discriminator == null) return null;
                    var ctx = PopContext();
                    if (ctx == null) return null;
                    var node = N(K.AnonymousDescriptor);
                    node.Add(ctx);
                    node.Add(discriminator);
                    return node;
                }
                case 'X': return PopContext() is { } c ? With(K.AnonymousDescriptor, c) : null;
                case 'A':
                {
                    var path = PopAssocTypePath();
                    if (path == null) return null;
                    var baseType = Pop(K.Type);
                    return baseType == null ? null : With(K.AssociatedTypeGenericParamRef, baseType, path);
                }
                default: return null;
            }
        }

        private SwiftNode? DemangleArchetype()
        {
            switch (Next())
            {
                case 'a':
                {
                    var ident = Pop(K.Identifier);
                    var arche = PopTypeAndGetChild();
                    var assoc = CreateType(With(K.AssociatedTypeRef, arche, ident));
                    AddSubstitution(assoc);
                    return assoc;
                }
                case 'O': return With(K.OpaqueReturnTypeOf, PopContext());
                case 'o':
                {
                    int index = DemangleIndex();
                    var lists = new List<SwiftNode>();
                    if (!DemangleBoundGenerics(lists, out var retro)) return null;
                    var name = Pop();
                    if (name == null) return null;
                    var opaque = With(K.OpaqueType, name, N(K.Index, (long)index))!;
                    var bound = N(K.TypeList);
                    for (int i = lists.Count; i-- > 0;) bound.Add(lists[i]);
                    opaque.Add(bound);
                    if (retro != null) opaque.Add(retro);
                    var ty = CreateType(opaque);
                    AddSubstitution(ty);
                    return ty;
                }
                case 'r': return CreateType(N(K.OpaqueReturnType));
                case 'R':
                {
                    int ordinal = DemangleIndex();
                    if (ordinal < 0) return null;
                    return CreateType(With(K.OpaqueReturnType, N(K.OpaqueReturnTypeIndex, (ulong)ordinal)));
                }
                case 'x':
                {
                    var t = DemangleAssociatedTypeSimple(null);
                    AddSubstitution(t);
                    return t;
                }
                case 'X':
                {
                    var t = DemangleAssociatedTypeCompound(null);
                    AddSubstitution(t);
                    return t;
                }
                case 'y':
                {
                    var t = DemangleAssociatedTypeSimple(DemangleGenericParamIndex());
                    AddSubstitution(t);
                    return t;
                }
                case 'Y':
                {
                    var t = DemangleAssociatedTypeCompound(DemangleGenericParamIndex());
                    AddSubstitution(t);
                    return t;
                }
                case 'z':
                {
                    var t = DemangleAssociatedTypeSimple(GetDependentGenericParamType(0, 0));
                    AddSubstitution(t);
                    return t;
                }
                case 'Z':
                {
                    var t = DemangleAssociatedTypeCompound(GetDependentGenericParamType(0, 0));
                    AddSubstitution(t);
                    return t;
                }
                case 'p':
                {
                    var count = PopTypeAndGetChild();
                    var pattern = PopTypeAndGetChild();
                    return CreateType(With(K.PackExpansion, pattern, count));
                }
                case 'e':
                {
                    var pack = PopTypeAndGetChild();
                    int level = DemangleIndex();
                    if (level < 0) return null;
                    return CreateType(With(K.PackElement, pack, N(K.PackElementLevel, (ulong)level)));
                }
                case 'P': return PopPack();
                case 'S': return PopSILPack();
                default: return null;
            }
        }

        private SwiftNode? DemangleAssociatedTypeSimple(SwiftNode? baseNode)
        {
            var name = PopAssocTypeName();
            var baseType = baseNode != null ? CreateType(baseNode) : Pop(K.Type);
            return CreateType(With(K.DependentMemberType, baseType, name));
        }

        private SwiftNode? DemangleAssociatedTypeCompound(SwiftNode? baseNode)
        {
            var names = new List<SwiftNode>(4);
            bool first;
            do
            {
                first = Pop(K.FirstElementMarker) != null;
                var name = PopAssocTypeName();
                if (name == null) return null;
                names.Add(name);
            } while (!first);
            var baseType = baseNode != null ? CreateType(baseNode) : Pop(K.Type);
            for (int i = names.Count - 1; i >= 0; i--)
            {
                var dep = AddChild(N(K.DependentMemberType), baseType);
                baseType = CreateType(AddChild(dep, names[i]));
            }
            return baseType;
        }

        private SwiftNode? PopAssocTypeName()
        {
            var proto = Pop(K.Type);
            if (proto != null && !IsProtocolNode(proto)) return null;
            proto ??= Pop(K.ProtocolSymbolicReference) ?? Pop(K.ObjectiveCProtocolSymbolicReference);
            var id = Pop(K.Identifier);
            var assoc = With(K.DependentAssociatedTypeRef, id);
            AddChild(assoc, proto);
            return assoc;
        }

        private SwiftNode? PopAssocTypePath()
        {
            var path = N(K.AssocTypePath);
            bool first;
            do
            {
                first = Pop(K.FirstElementMarker) != null;
                var assoc = PopAssocTypeName();
                if (assoc == null) return null;
                path.Add(assoc);
            } while (!first);
            path.Reverse();
            return path;
        }

        private SwiftNode? GetDependentGenericParamType(int depth, int index)
        {
            if (depth < 0 || index < 0) return null;
            var p = N(K.DependentGenericParamType);
            p.Add(N(K.Index, (ulong)depth));
            p.Add(N(K.Index, (ulong)index));
            return p;
        }

        private SwiftNode? DemangleGenericParamIndex()
        {
            if (NextIf('d'))
            {
                int depth = DemangleIndex() + 1;
                int index = DemangleIndex();
                return GetDependentGenericParamType(depth, index);
            }
            if (NextIf('z')) return GetDependentGenericParamType(0, 0);
            if (NextIf('s')) return N(K.ConstrainedExistentialSelf);
            return GetDependentGenericParamType(0, DemangleIndex() + 1);
        }

        private SwiftNode? PopProtocolConformance()
        {
            var sig = Pop(K.DependentGenericSignature);
            var module = PopModule();
            var proto = PopProtocol();
            var type = Pop(K.Type);
            SwiftNode? ident = null;
            if (type == null)
            {
                ident = Pop(K.Identifier);
                type = Pop(K.Type);
            }
            if (sig != null) type = CreateType(With(K.DependentGenericType, sig, type));
            var conf = With(K.ProtocolConformance, type, proto, module);
            AddChild(conf, ident);
            return conf;
        }

        private SwiftNode? PopAssociatedConformanceWitnessAccessorSubject()
        {
            if (Pop(K.Type) is { } type)
            {
                if (IsGenericParamType(type)) return type;
                Push(type);
            }
            return PopAssocTypePath();
        }

        private SwiftNode? DemangleThunkOrSpecialization()
        {
            char c = Next();
            switch (c)
            {
                case 'T': return Next() == 'I' ? With(K.SILThunkIdentity, Pop(IsEntity)) : null;
                case 'c': return With(K.CurryThunk, Pop(IsEntity));
                case 'j': return With(K.DispatchThunk, Pop(IsEntity));
                case 'q': return With(K.MethodDescriptor, Pop(IsEntity));
                case 'o': return N(K.ObjCAttribute);
                case 'O': return N(K.NonObjCAttribute);
                case 'D': return N(K.DynamicAttribute);
                case 'd': return N(K.DirectMethodReferenceAttribute);
                case 'E': return N(K.DistributedThunk);
                case 'F': return N(K.DistributedAccessor);
                case 'a': return N(K.PartialApplyObjCForwarder);
                case 'A': return N(K.PartialApplyForwarder);
                case 'm': return N(K.MergedFunction);
                case 'X': return N(K.DynamicallyReplaceableFunctionVar);
                case 'x': return N(K.DynamicallyReplaceableFunctionKey);
                case 'I': return N(K.DynamicallyReplaceableFunctionImpl);
                case 'Y' or 'Q':
                    return With(c == 'Q' ? K.AsyncAwaitResumePartialFunction : K.AsyncSuspendResumePartialFunction, DemangleIndexAsNode());
                case 'C': return With(K.CoroutineContinuationPrototype, Pop(K.Type));
                case 'z' or 'Z':
                {
                    var flag = DemangleIndexAsNode();
                    var sig = Pop(K.DependentGenericSignature);
                    var resultType = Pop(K.Type);
                    var implType = Pop(K.Type);
                    var node = With(c == 'z' ? K.ObjCAsyncCompletionHandlerImpl : K.CheckedObjCAsyncCompletionHandlerImpl, implType, resultType, flag);
                    if (sig != null) AddChild(node, sig);
                    return node;
                }
                case 'V':
                {
                    var baseEntity = Pop(IsEntity);
                    var derived = Pop(IsEntity);
                    return With(K.VTableThunk, derived, baseEntity);
                }
                case 'W':
                {
                    var entity = Pop(IsEntity);
                    var conf = PopProtocolConformance();
                    return With(K.ProtocolWitness, conf, entity);
                }
                case 'S': return With(K.ProtocolSelfConformanceWitness, Pop(IsEntity));
                case 'R' or 'r' or 'y':
                {
                    var kind = c == 'R' ? K.ReabstractionThunkHelper : c == 'y' ? K.ReabstractionThunkHelperWithSelf : K.ReabstractionThunk;
                    SwiftNode? thunk = N(kind);
                    if (Pop(K.DependentGenericSignature) is { } sig) AddChild(thunk, sig);
                    if (kind == K.ReabstractionThunkHelperWithSelf) thunk = AddChild(thunk, Pop(K.Type));
                    thunk = AddChild(thunk, Pop(K.Type));
                    return AddChild(thunk, Pop(K.Type));
                }
                case 'g': return DemangleGenericSpecialization(K.GenericSpecialization, null);
                case 'G': return DemangleGenericSpecialization(K.GenericSpecializationNotReAbstracted, null);
                case 'B': return DemangleGenericSpecialization(K.GenericSpecializationInResilienceDomain, null);
                case 't': return DemangleGenericSpecializationWithDroppedArguments();
                case 's': return DemangleGenericSpecialization(K.GenericSpecializationPrespecialized, null);
                case 'i': return DemangleGenericSpecialization(K.InlinedGenericFunction, null);
                case 'p' or 'P':
                {
                    var spec = DemangleSpecAttributes(c == 'p' ? K.GenericPartialSpecialization : K.GenericPartialSpecializationNotReAbstracted);
                    var param = With(K.GenericSpecializationParam, Pop(K.Type));
                    return AddChild(spec, param);
                }
                case 'f': return DemangleFunctionSpecialization();
                case 'K' or 'k':
                {
                    K kind = NextIf("mu") ? K.KeyPathUnappliedMethodThunkHelper : NextIf("MA") ? K.KeyPathAppliedMethodThunkHelper
                        : c == 'K' ? K.KeyPathGetterThunkHelper : K.KeyPathSetterThunkHelper;
                    bool serialized = NextIf('q');
                    var types = new List<SwiftNode>();
                    var node = Pop();
                    if (node == null || node.Kind != K.Type) return null;
                    do
                    {
                        types.Add(node);
                        node = Pop();
                    } while (node != null && node.Kind == K.Type);
                    SwiftNode? result;
                    if (node == null) return null;
                    if (node.Kind == K.DependentGenericSignature)
                    {
                        var decl = Pop();
                        if (decl == null) return null;
                        result = With(kind, decl, node);
                    }
                    else result = With(kind, node);
                    for (int i = types.Count - 1; i >= 0; i--) result!.Add(types[i]);
                    if (serialized) result!.Add(N(K.IsSerialized));
                    return result;
                }
                case 'l': return PopAssocTypeName() is { } assoc ? With(K.AssociatedTypeDescriptor, assoc) : null;
                case 'L': return With(K.ProtocolRequirementsBaseDescriptor, PopProtocol());
                case 'M': return With(K.DefaultAssociatedTypeMetadataAccessor, PopAssocTypeName());
                case 'n' or 'N':
                {
                    var requirement = PopProtocol();
                    var subject = PopAssociatedConformanceWitnessAccessorSubject();
                    var protoType = Pop(K.Type);
                    return With(c == 'n' ? K.AssociatedConformanceDescriptor : K.DefaultAssociatedConformanceAccessor, protoType, subject, requirement);
                }
                case 'b':
                {
                    var requirement = PopProtocol();
                    var protoType = Pop(K.Type);
                    return With(K.BaseConformanceDescriptor, protoType, requirement);
                }
                case 'H' or 'h':
                {
                    var kind = c == 'H' ? K.KeyPathEqualsThunkHelper : K.KeyPathHashThunkHelper;
                    bool serialized = NextIf('q');
                    SwiftNode? sig = null;
                    var types = new List<SwiftNode>();
                    var node = Pop();
                    if (node == null) return null;
                    if (node.Kind == K.DependentGenericSignature) sig = node;
                    else if (node.Kind == K.Type) types.Add(node);
                    else return null;
                    while (Pop() is { } more)
                    {
                        if (more.Kind != K.Type) return null;
                        types.Add(more);
                    }
                    var result = N(kind);
                    for (int i = types.Count - 1; i >= 0; i--) result.Add(types[i]);
                    if (sig != null) result.Add(sig);
                    if (serialized) result.Add(N(K.IsSerialized));
                    return result;
                }
                case 'v':
                {
                    int idx = DemangleIndex();
                    if (idx < 0) return null;
                    return Next() == 'r' ? N(K.OutlinedReadOnlyObject, (ulong)idx) : N(K.OutlinedVariable, (ulong)idx);
                }
                case 'e':
                {
                    var p = DemangleBridgedMethodParams();
                    return p.Length == 0 ? null : N(K.OutlinedBridgedMethod, p);
                }
                case 'u': return N(K.AsyncFunctionPointer);
                case 'U':
                {
                    var actor = Pop(K.Type);
                    if (actor == null) return null;
                    var reabstraction = Pop();
                    if (reabstraction == null) return null;
                    var node = N(K.ReabstractionThunkHelperWithGlobalActor);
                    node.Add(reabstraction);
                    node.Add(actor);
                    return node;
                }
                case 'J':
                    switch (Peek())
                    {
                        case 'S': Next(); return DemangleAutoDiffSubsetParametersThunk();
                        case 'O': Next(); return DemangleAutoDiffSelfReorderingReabstractionThunk();
                        case 'V': Next(); return DemangleAutoDiffFunctionOrSimpleThunk(K.AutoDiffDerivativeVTableThunk);
                        default: return DemangleAutoDiffFunctionOrSimpleThunk(K.AutoDiffFunction);
                    }
                case 'w':
                    return Next() switch
                    {
                        'b' => N(K.BackDeploymentThunk),
                        'B' => N(K.BackDeploymentFallback),
                        'c' => N(K.CoroFunctionPointer),
                        'd' => N(K.DefaultOverride),
                        'S' => N(K.HasSymbolQuery),
                        _ => null,
                    };
                default: return null;
            }
        }

        private SwiftNode? DemangleAutoDiffFunctionOrSimpleThunk(K kind)
        {
            SwiftNode? result = N(kind);
            while (Pop() is { } original) result = AddChild(result, original);
            result?.Reverse();
            result = AddChild(result, DemangleAutoDiffFunctionKind());
            result = AddChild(result, DemangleIndexSubset());
            if (!NextIf('p')) return null;
            result = AddChild(result, DemangleIndexSubset());
            return NextIf('r') ? result : null;
        }

        private SwiftNode? DemangleAutoDiffFunctionKind()
        {
            char k = Next();
            return k is 'f' or 'r' or 'd' or 'p' ? N(K.AutoDiffFunctionKind, k) : null;
        }

        private SwiftNode? DemangleAutoDiffSubsetParametersThunk()
        {
            SwiftNode? result = N(K.AutoDiffSubsetParametersThunk);
            while (Pop() is { } node) result = AddChild(result, node);
            result?.Reverse();
            result = AddChild(result, DemangleAutoDiffFunctionKind());
            result = AddChild(result, DemangleIndexSubset());
            if (!NextIf('p')) return null;
            result = AddChild(result, DemangleIndexSubset());
            if (!NextIf('r')) return null;
            result = AddChild(result, DemangleIndexSubset());
            return NextIf('P') ? result : null;
        }

        private SwiftNode? DemangleAutoDiffSelfReorderingReabstractionThunk()
        {
            SwiftNode? result = N(K.AutoDiffSelfReorderingReabstractionThunk);
            AddChild(result, Pop(K.DependentGenericSignature));
            result = AddChild(result, Pop(K.Type));
            result = AddChild(result, Pop(K.Type));
            result?.Reverse();
            return AddChild(result, DemangleAutoDiffFunctionKind());
        }

        private SwiftNode? DemangleDifferentiabilityWitness()
        {
            SwiftNode? result = N(K.DifferentiabilityWitness);
            var sig = Pop(K.DependentGenericSignature);
            while (Pop() is { } node) result = AddChild(result, node);
            result?.Reverse();
            char kind = Next();
            if (kind is not ('f' or 'r' or 'd' or 'l')) return null;
            result = AddChild(result, N(K.Index, kind));
            result = AddChild(result, DemangleIndexSubset());
            if (!NextIf('p')) return null;
            result = AddChild(result, DemangleIndexSubset());
            if (!NextIf('r')) return null;
            AddChild(result, sig);
            return result;
        }

        private SwiftNode? DemangleIndexSubset()
        {
            var sb = new StringBuilder();
            for (char c = Peek(); c is 'S' or 'U'; c = Peek())
            {
                sb.Append(c);
                Next();
            }
            return sb.Length == 0 ? null : N(K.IndexSubset, sb.ToString());
        }

        private SwiftNode? DemangleDifferentiableFunctionType()
        {
            char kind = Next();
            return kind is 'f' or 'r' or 'd' or 'l' ? N(K.DifferentiableFunctionType, kind) : null;
        }

        private string DemangleBridgedMethodParams()
        {
            if (NextIf('_')) return "";
            var sb = new StringBuilder();
            char kind = Next();
            if (kind is not ('o' or 'p' or 'a' or 'm')) return "";
            sb.Append(kind);
            while (!NextIf('_'))
            {
                char c = Next();
                if (c is not ('n' or 'b' or 'g')) return "";
                sb.Append(c);
            }
            return sb.ToString();
        }

        private SwiftNode? DemangleGenericSpecialization(K kind, SwiftNode? dropped)
        {
            var spec = DemangleSpecAttributes(kind);
            if (spec == null) return null;
            if (dropped != null)
                foreach (var a in dropped.Children) spec.Add(a);
            var list = PopTypeList();
            if (list == null) return null;
            foreach (var ty in list.Children) spec.Add(With(K.GenericSpecializationParam, ty)!);
            return spec;
        }

        private SwiftNode? DemangleGenericSpecializationWithDroppedArguments()
        {
            PushBack();
            var tmp = N(K.GenericSpecialization);
            while (NextIf('t'))
            {
                int n = DemangleNatural();
                tmp.Add(N(K.DroppedArgument, (ulong)(n < 0 ? 0 : n + 1)));
            }
            K kind;
            switch (Next())
            {
                case 'g': kind = K.GenericSpecialization; break;
                case 'G': kind = K.GenericSpecializationNotReAbstracted; break;
                case 'B': kind = K.GenericSpecializationInResilienceDomain; break;
                default: return null;
            }
            return DemangleGenericSpecialization(kind, tmp);
        }

        private SwiftNode? DemangleFunctionSpecialization()
        {
            var spec = DemangleSpecAttributes(K.FunctionSignatureSpecialization);
            if (spec != null && spec.First!.Kind == K.RepresentationChanged) return spec;
            while (spec != null && !NextIf('_')) spec = AddChild(spec, DemangleFuncSpecParam(K.FunctionSignatureSpecializationParam));
            if (!NextIf('n')) spec = AddChild(spec, DemangleFuncSpecParam(K.FunctionSignatureSpecializationReturn));
            if (spec == null) return null;

            for (int idx = 0, num = spec.Count; idx < num; idx++)
            {
                var param = spec[num - idx - 1]!;
                if (param.Kind != K.FunctionSignatureSpecializationParam) continue;
                int fixedChildren = param.Count;
                SwiftNode? toAdd = param;
                for (int ci = 0; ci < fixedChildren; ci++)
                {
                    var kindNode = param[fixedChildren - ci - 1]!;
                    if (kindNode.Kind != K.FunctionSignatureSpecializationParamKind) continue;
                    switch ((FuncSigParamKind)kindNode.Index)
                    {
                        case FuncSigParamKind.ClosureProp or FuncSigParamKind.EscapingClosureProp:
                            while (Pop(K.Type) is { } ty) toAdd = AddChild(toAdd, ty);
                            break;
                        case FuncSigParamKind.ConstantPropKeyPath:
                            toAdd = AddChild(toAdd, Pop(K.Type));
                            toAdd = AddChild(toAdd, Pop(K.Type));
                            break;
                        case FuncSigParamKind.ConstantPropStruct:
                            toAdd = AddChild(toAdd, Pop(K.Type));
                            continue;
                        case FuncSigParamKind.ConstantPropFunction or FuncSigParamKind.ConstantPropGlobal or FuncSigParamKind.ConstantPropString:
                            break;
                        default:
                            continue;
                    }
                    toAdd = AddChild(toAdd, Pop(K.Identifier));
                }
                if (toAdd == null) return null;
                param.Reverse(fixedChildren);
            }
            return spec;
        }

        private SwiftNode? DemangleFuncSpecParam(K kind)
        {
            var param = N(kind);
            SwiftNode ParamKind(FuncSigParamKind k) => N(K.FunctionSignatureSpecializationParamKind, (ulong)k);
            switch (Next())
            {
                case 'n': return param;
                case 'c': return AddChild(param, ParamKind(FuncSigParamKind.ClosureProp));
                case 'E': return AddChild(param, ParamKind(FuncSigParamKind.EscapingClosureProp));
                case 'C':
                {
                    AddChild(param, ParamKind(FuncSigParamKind.ClosurePropPreviousArg));
                    int prev = DemangleNatural();
                    if (prev < 0) return null;
                    return AddChild(param, N(K.FunctionSignatureSpecializationParamPayload, (ulong)prev));
                }
                case 'p':
                    while (true)
                    {
                        switch (Next())
                        {
                            case 'S': AddChild(param, ParamKind(FuncSigParamKind.ConstantPropStruct)); break;
                            case 'f': AddChild(param, ParamKind(FuncSigParamKind.ConstantPropFunction)); break;
                            case 'g': AddChild(param, ParamKind(FuncSigParamKind.ConstantPropGlobal)); break;
                            case 'i':
                                if (AddFuncSpecParamNumber(param, FuncSigParamKind.ConstantPropInteger) == null) return null;
                                break;
                            case 'd':
                                if (AddFuncSpecParamNumber(param, FuncSigParamKind.ConstantPropFloat) == null) return null;
                                break;
                            case 's':
                            {
                                string? encoding = Next() switch { 'b' => "u8", 'w' => "u16", 'c' => "objc", _ => null };
                                if (encoding == null) return null;
                                AddChild(param, ParamKind(FuncSigParamKind.ConstantPropString));
                                AddChild(param, N(K.FunctionSignatureSpecializationParamPayload, encoding));
                                break;
                            }
                            case 'k': AddChild(param, ParamKind(FuncSigParamKind.ConstantPropKeyPath)); break;
                            default:
                                PushBack();
                                return param;
                        }
                    }
                case 'e':
                {
                    var v = FuncSigParamKind.ExistentialToGeneric;
                    if (NextIf('D')) v |= FuncSigParamKind.Dead;
                    if (NextIf('G')) v |= FuncSigParamKind.OwnedToGuaranteed;
                    if (NextIf('O')) v |= FuncSigParamKind.GuaranteedToOwned;
                    if (NextIf('X')) v |= FuncSigParamKind.SROA;
                    return AddChild(param, ParamKind(v));
                }
                case 'd':
                {
                    var v = FuncSigParamKind.Dead;
                    if (NextIf('G')) v |= FuncSigParamKind.OwnedToGuaranteed;
                    if (NextIf('O')) v |= FuncSigParamKind.GuaranteedToOwned;
                    if (NextIf('X')) v |= FuncSigParamKind.SROA;
                    return AddChild(param, ParamKind(v));
                }
                case 'g':
                {
                    var v = FuncSigParamKind.OwnedToGuaranteed;
                    if (NextIf('X')) v |= FuncSigParamKind.SROA;
                    return AddChild(param, ParamKind(v));
                }
                case 'o':
                {
                    var v = FuncSigParamKind.GuaranteedToOwned;
                    if (NextIf('X')) v |= FuncSigParamKind.SROA;
                    return AddChild(param, ParamKind(v));
                }
                case 'x': return AddChild(param, ParamKind(FuncSigParamKind.SROA));
                case 'i': return AddChild(param, ParamKind(FuncSigParamKind.BoxToValue));
                case 's': return AddChild(param, ParamKind(FuncSigParamKind.BoxToStack));
                case 'r': return AddChild(param, ParamKind(FuncSigParamKind.InOutToOut));
                default: return null;
            }
        }

        private SwiftNode? AddFuncSpecParamNumber(SwiftNode param, FuncSigParamKind kind)
        {
            param.Add(N(K.FunctionSignatureSpecializationParamKind, (ulong)kind));
            var sb = new StringBuilder();
            while (IsDigit(Peek())) sb.Append(Next());
            return sb.Length == 0 ? null : AddChild(param, N(K.FunctionSignatureSpecializationParamPayload, sb.ToString()));
        }

        private SwiftNode? DemangleSpecAttributes(K kind)
        {
            bool serialized = NextIf('q');
            bool asyncRemoved = NextIf('a');
            bool representationChanged = NextIf('r');
            int passId = Next() - '0';
            if (passId is < 0 or >= MaxSpecializationPass) return null;
            var spec = N(kind);
            if (serialized) spec.Add(N(K.IsSerialized));
            if (asyncRemoved) spec.Add(N(K.AsyncRemoved));
            if (representationChanged) spec.Add(N(K.RepresentationChanged));
            spec.Add(N(K.SpecializationPassID, (ulong)passId));
            return spec;
        }

        private SwiftNode? DemangleWitness()
        {
            char c = Next();
            switch (c)
            {
                case 'C': return With(K.EnumCase, Pop(IsEntity));
                case 'V': return With(K.ValueWitnessTable, Pop(K.Type));
                case 'v':
                {
                    ulong directness;
                    switch (Next())
                    {
                        case 'd': directness = 0; break;
                        case 'i': directness = 1; break;
                        default: return null;
                    }
                    return With(K.FieldOffset, N(K.Directness, directness), Pop(IsEntity));
                }
                case 'S': return With(K.ProtocolSelfConformanceWitnessTable, PopProtocol());
                case 'P': return With(K.ProtocolWitnessTable, PopProtocolConformance());
                case 'p': return With(K.ProtocolWitnessTablePattern, PopProtocolConformance());
                case 'G': return With(K.GenericProtocolWitnessTable, PopProtocolConformance());
                case 'I': return With(K.GenericProtocolWitnessTableInstantiationFunction, PopProtocolConformance());
                case 'r': return With(K.ResilientProtocolWitnessTable, PopProtocolConformance());
                case 'l' or 'L':
                {
                    var conf = PopProtocolConformance();
                    var type = Pop(K.Type);
                    return With(c == 'l' ? K.LazyProtocolWitnessTableAccessor : K.LazyProtocolWitnessTableCacheVariable, type, conf);
                }
                case 'a': return With(K.ProtocolWitnessTableAccessor, PopProtocolConformance());
                case 't':
                {
                    var name = Pop(IsDeclName);
                    var conf = PopProtocolConformance();
                    return With(K.AssociatedTypeMetadataAccessor, conf, name);
                }
                case 'T':
                {
                    var protoType = Pop(K.Type);
                    var conforming = PopAssocTypePath();
                    var conf = PopProtocolConformance();
                    return With(K.AssociatedTypeWitnessTableAccessor, conf, conforming, protoType);
                }
                case 'b':
                {
                    var protoType = Pop(K.Type);
                    var conf = PopProtocolConformance();
                    return With(K.BaseWitnessTableAccessor, conf, protoType);
                }
                case 'O':
                {
                    K? kind = Next() switch
                    {
                        'B' => K.OutlinedInitializeWithTakeNoValueWitness,
                        'C' => K.OutlinedInitializeWithCopyNoValueWitness,
                        'D' => K.OutlinedAssignWithTakeNoValueWitness,
                        'F' => K.OutlinedAssignWithCopyNoValueWitness,
                        'H' => K.OutlinedDestroyNoValueWitness,
                        'y' => K.OutlinedCopy,
                        'e' => K.OutlinedConsume,
                        'r' => K.OutlinedRetain,
                        's' => K.OutlinedRelease,
                        'b' => K.OutlinedInitializeWithTake,
                        'c' => K.OutlinedInitializeWithCopy,
                        'd' => K.OutlinedAssignWithTake,
                        'f' => K.OutlinedAssignWithCopy,
                        'h' => K.OutlinedDestroy,
                        'g' => K.OutlinedEnumGetTag,
                        'i' => K.OutlinedEnumTagStore,
                        'j' => K.OutlinedEnumProjectDataForLoad,
                        _ => null,
                    };
                    if (kind is not { } k) return null;
                    if (k is K.OutlinedEnumTagStore or K.OutlinedEnumProjectDataForLoad)
                    {
                        var caseIdx = DemangleIndexAsNode();
                        if (Pop(K.DependentGenericSignature) is { } sig) return With(k, Pop(K.Type), sig, caseIdx);
                        return With(k, Pop(K.Type), caseIdx);
                    }
                    if (Pop(K.DependentGenericSignature) is { } s) return With(k, Pop(K.Type), s);
                    return With(k, Pop(K.Type));
                }
                case 'Z' or 'z':
                {
                    var declList = N(K.GlobalVariableOnceDeclList);
                    var vars = new List<SwiftNode>();
                    while (Pop(K.FirstElementMarker) != null)
                    {
                        var ident = Pop(IsDeclName);
                        if (ident == null) return null;
                        vars.Add(ident);
                    }
                    for (int i = vars.Count - 1; i >= 0; i--) declList.Add(vars[i]);
                    var ctx = PopContext();
                    if (ctx == null) return null;
                    return With(c == 'Z' ? K.GlobalVariableOnceFunction : K.GlobalVariableOnceToken, ctx, declList);
                }
                case 'J': return DemangleDifferentiabilityWitness();
                default: return null;
            }
        }

        private SwiftNode? DemangleSpecialType()
        {
            char special = Next();
            switch (special)
            {
                case 'E': return PopFunctionType(K.NoEscapeFunctionType);
                case 'A': return PopFunctionType(K.EscapingAutoClosureType);
                case 'f': return PopFunctionType(K.ThinFunctionType);
                case 'K': return PopFunctionType(K.AutoClosureType);
                case 'U': return PopFunctionType(K.UncurriedFunctionType);
                case 'L': return PopFunctionType(K.EscapingObjCBlock);
                case 'B': return PopFunctionType(K.ObjCBlock);
                case 'C': return PopFunctionType(K.CFunctionPointer);
                case 'O': return NextIf('o') ? PopFunctionType(K.CalledAtMostOnceFunctionType) : PopFunctionType(K.CalledOnceFunctionType);
                case 'g' or 'G': return DemangleExtendedExistentialShape(special);
                case 'j': return DemangleSymbolicExtendedExistentialType();
                case 'y':
                {
                    var yields = Pop(K.EmptyList) != null ? CreateType(N(K.Tuple)) : Pop(K.Type);
                    return With(K.YieldTypes, yields);
                }
                case 'z':
                    return Next() switch
                    {
                        'B' => PopFunctionType(K.ObjCBlock, true),
                        'C' => PopFunctionType(K.CFunctionPointer, true),
                        _ => null,
                    };
                case 'o': return CreateType(With(K.Unowned, Pop(K.Type)));
                case 'u': return CreateType(With(K.Unmanaged, Pop(K.Type)));
                case 'w': return CreateType(With(K.Weak, Pop(K.Type)));
                case 'b': return CreateType(With(K.SILBoxType, Pop(K.Type)));
                case 'D': return CreateType(With(K.DynamicSelf, Pop(K.Type)));
                case 'M':
                {
                    var repr = DemangleMetatypeRepresentation();
                    var type = Pop(K.Type);
                    return CreateType(With(K.Metatype, repr, type));
                }
                case 'm':
                {
                    var repr = DemangleMetatypeRepresentation();
                    var type = Pop(K.Type);
                    return CreateType(With(K.ExistentialMetatype, repr, type));
                }
                case 'P':
                {
                    var reqs = DemangleConstrainedExistentialRequirementList();
                    var baseType = Pop(K.Type);
                    return CreateType(With(K.ConstrainedExistential, baseType, reqs));
                }
                case 'p': return CreateType(With(K.ExistentialMetatype, Pop(K.Type)));
                case 'c':
                {
                    var superclass = Pop(K.Type);
                    var protocols = DemangleProtocolList();
                    return CreateType(With(K.ProtocolListWithClass, protocols, superclass));
                }
                case 'l': return CreateType(With(K.ProtocolListWithAnyObject, DemangleProtocolList()));
                case 'X' or 'x':
                {
                    SwiftNode? signature = null, genericArgs = null;
                    if (special == 'X')
                    {
                        signature = Pop(K.DependentGenericSignature);
                        if (signature == null) return null;
                        genericArgs = PopTypeList();
                        if (genericArgs == null) return null;
                    }
                    var fieldTypes = PopTypeList();
                    if (fieldTypes == null) return null;
                    var layout = N(K.SILBoxLayout);
                    foreach (var f in fieldTypes.Children)
                    {
                        var fieldType = f;
                        bool mutable = false;
                        if (fieldType.First!.Kind == K.InOut)
                        {
                            mutable = true;
                            fieldType = CreateType(fieldType.First.First)!;
                        }
                        var field = N(mutable ? K.SILBoxMutableField : K.SILBoxImmutableField);
                        field.Add(fieldType);
                        layout.Add(field);
                    }
                    var box = N(K.SILBoxTypeWithLayout);
                    box.Add(layout);
                    if (signature != null)
                    {
                        box.Add(signature);
                        box.Add(genericArgs!);
                    }
                    return CreateType(box);
                }
                case 'Y': return DemangleAnyGenericType(K.OtherNominalType);
                case 'Z':
                {
                    var types = PopTypeList();
                    var name = Pop(K.Identifier);
                    var parent = PopContext();
                    SwiftNode? anon = N(K.AnonymousContext);
                    anon = AddChild(anon, name);
                    anon = AddChild(anon, parent);
                    return AddChild(anon, types);
                }
                case 'e': return CreateType(N(K.ErrorType));
                case 'S':
                    switch (Next())
                    {
                        case 'q': return CreateType(With(K.SugaredOptional, Pop(K.Type)));
                        case 'a': return CreateType(With(K.SugaredArray, Pop(K.Type)));
                        case 'A':
                        {
                            var element = Pop(K.Type);
                            var count = Pop(K.Type);
                            return CreateType(With(K.SugaredInlineArray, count, element));
                        }
                        case 'D':
                        {
                            var value = Pop(K.Type);
                            var key = Pop(K.Type);
                            return CreateType(With(K.SugaredDictionary, key, value));
                        }
                        case 'p': return CreateType(With(K.SugaredParen, Pop(K.Type)));
                        default: return null;
                    }
                default: return null;
            }
        }

        private SwiftNode? DemangleSymbolicExtendedExistentialType()
        {
            var retro = PopRetroactiveConformances();
            var args = N(K.TypeList);
            while (Pop(K.Type) is { } ty) args.Add(ty);
            args.Reverse();
            var shape = Pop();
            if (shape == null || shape.Kind is not (K.UniqueExtendedExistentialTypeShapeSymbolicReference or K.NonUniqueExtendedExistentialTypeShapeSymbolicReference))
                return null;
            return CreateType(retro == null ? With(K.SymbolicExtendedExistentialType, shape, args) : With(K.SymbolicExtendedExistentialType, shape, args, retro));
        }

        private SwiftNode? DemangleExtendedExistentialShape(char kind)
        {
            var type = Pop(K.Type);
            var sig = kind == 'G' ? Pop(K.DependentGenericSignature) : null;
            return sig != null ? With(K.ExtendedExistentialTypeShape, sig, type) : With(K.ExtendedExistentialTypeShape, type);
        }

        private SwiftNode? DemangleMetatypeRepresentation() => Next() switch
        {
            't' => N(K.MetatypeRepresentation, "@thin"),
            'T' => N(K.MetatypeRepresentation, "@thick"),
            'o' => N(K.MetatypeRepresentation, "@objc_metatype"),
            _ => null,
        };

        private SwiftNode? DemangleAccessor(SwiftNode? child)
        {
            K kind;
            switch (Next())
            {
                case 'm': kind = K.MaterializeForSet; break;
                case 's': kind = K.Setter; break;
                case 'g': kind = K.Getter; break;
                case 'G': kind = K.GlobalGetter; break;
                case 'w': kind = K.WillSet; break;
                case 'W': kind = K.DidSet; break;
                case 'r': kind = K.ReadAccessor; break;
                case 'y': kind = K.YieldingBorrowAccessor; break;
                case 'M': kind = K.ModifyAccessor; break;
                case 'x': kind = K.YieldingMutateAccessor; break;
                case 'i': kind = K.InitAccessor; break;
                case 'b': kind = K.BorrowAccessor; break;
                case 'z': kind = K.MutateAccessor; break;
                case 'a':
                    switch (Next())
                    {
                        case 'O': kind = K.OwningMutableAddressor; break;
                        case 'o': kind = K.NativeOwningMutableAddressor; break;
                        case 'P': kind = K.NativePinningMutableAddressor; break;
                        case 'u': kind = K.UnsafeMutableAddressor; break;
                        default: return null;
                    }
                    break;
                case 'l':
                    switch (Next())
                    {
                        case 'O': kind = K.OwningAddressor; break;
                        case 'o': kind = K.NativeOwningAddressor; break;
                        case 'p': kind = K.NativePinningAddressor; break;
                        case 'u': kind = K.UnsafeAddressor; break;
                        default: return null;
                    }
                    break;
                case 'p': return child;
                default: return null;
            }
            return With(kind, child);
        }

        private enum EntityArgs { None, TypeAndMaybePrivateName, TypeAndIndex, Index }

        private SwiftNode? DemangleFunctionEntity()
        {
            EntityArgs args;
            K kind;
            switch (Next())
            {
                case 'D': args = EntityArgs.None; kind = K.Deallocator; break;
                case 'd': args = EntityArgs.None; kind = K.Destructor; break;
                case 'Z': args = EntityArgs.None; kind = K.IsolatedDeallocator; break;
                case 'E': args = EntityArgs.None; kind = K.IVarDestroyer; break;
                case 'e': args = EntityArgs.None; kind = K.IVarInitializer; break;
                case 'i': args = EntityArgs.None; kind = K.Initializer; break;
                case 'C': args = EntityArgs.TypeAndMaybePrivateName; kind = K.Allocator; break;
                case 'c': args = EntityArgs.TypeAndMaybePrivateName; kind = K.Constructor; break;
                case 'U': args = EntityArgs.TypeAndIndex; kind = K.ExplicitClosure; break;
                case 'u': args = EntityArgs.TypeAndIndex; kind = K.ImplicitClosure; break;
                case 'A': args = EntityArgs.Index; kind = K.DefaultArgumentInitializer; break;
                case 'm': return DemangleEntity(K.Macro);
                case 'M': return DemangleMacroExpansion();
                case 'p': return DemangleEntity(K.GenericTypeParamDecl);
                case 'P': args = EntityArgs.None; kind = K.PropertyWrapperBackingInitializer; break;
                case 'F': args = EntityArgs.None; kind = K.PropertyWrappedFieldInitAccessor; break;
                case 'W': args = EntityArgs.None; kind = K.PropertyWrapperInitFromProjectedValue; break;
                default: return null;
            }
            SwiftNode? nameOrIndex = null, paramType = null, labels = null;
            switch (args)
            {
                case EntityArgs.TypeAndMaybePrivateName:
                    nameOrIndex = Pop(K.PrivateDeclName);
                    paramType = Pop(K.Type);
                    labels = PopFunctionParamLabels(paramType);
                    break;
                case EntityArgs.TypeAndIndex:
                    nameOrIndex = DemangleIndexAsNode();
                    paramType = Pop(K.Type);
                    break;
                case EntityArgs.Index:
                    nameOrIndex = DemangleIndexAsNode();
                    break;
            }
            var entity = With(kind, PopContext());
            switch (args)
            {
                case EntityArgs.Index:
                    entity = AddChild(entity, nameOrIndex);
                    break;
                case EntityArgs.TypeAndMaybePrivateName:
                    AddChild(entity, labels);
                    entity = AddChild(entity, paramType);
                    AddChild(entity, nameOrIndex);
                    break;
                case EntityArgs.TypeAndIndex:
                    entity = AddChild(entity, nameOrIndex);
                    entity = AddChild(entity, paramType);
                    break;
            }
            return entity;
        }

        private SwiftNode? DemangleEntity(K kind)
        {
            var type = Pop(K.Type);
            var labels = PopFunctionParamLabels(type);
            var name = Pop(IsDeclName);
            var ctx = PopContext();
            var result = labels != null ? With(kind, ctx, name, labels, type) : With(kind, ctx, name, type);
            return SetParentForOpaqueReturnTypeNodes(result, type);
        }

        private SwiftNode? DemangleVariable() => DemangleAccessor(DemangleEntity(K.Variable));

        private SwiftNode? DemangleSubscript()
        {
            var privateName = Pop(K.PrivateDeclName);
            var type = Pop(K.Type);
            var labels = PopFunctionParamLabels(type);
            var ctx = PopContext();
            if (type == null) return null;
            SwiftNode? subscript = N(K.Subscript);
            subscript = AddChild(subscript, ctx);
            AddChild(subscript, labels);
            subscript = AddChild(subscript, type);
            AddChild(subscript, privateName);
            subscript = SetParentForOpaqueReturnTypeNodes(subscript, type);
            return DemangleAccessor(subscript);
        }

        private SwiftNode? DemangleProtocolList()
        {
            var list = N(K.TypeList);
            var protoList = With(K.ProtocolList, list);
            if (Pop(K.EmptyList) == null)
            {
                bool first;
                do
                {
                    first = Pop(K.FirstElementMarker) != null;
                    var proto = PopProtocol();
                    if (proto == null) return null;
                    list.Add(proto);
                } while (!first);
                list.Reverse();
            }
            return protoList;
        }

        private SwiftNode? DemangleProtocolListType() => CreateType(DemangleProtocolList());

        private SwiftNode? DemangleConstrainedExistentialRequirementList()
        {
            var list = N(K.ConstrainedExistentialRequirementList);
            bool first;
            do
            {
                first = Pop(K.FirstElementMarker) != null;
                var req = Pop(IsRequirement);
                if (req == null) return null;
                list.Add(req);
            } while (!first);
            list.Reverse();
            return list;
        }

        private SwiftNode? DemangleGenericSignature(bool hasParamCounts)
        {
            var sig = N(K.DependentGenericSignature);
            if (hasParamCounts)
            {
                while (!NextIf('l'))
                {
                    int count = 0;
                    if (!NextIf('z')) count = DemangleIndex() + 1;
                    if (count < 0) return null;
                    sig.Add(N(K.DependentGenericParamCount, (ulong)count));
                }
            }
            else sig.Add(N(K.DependentGenericParamCount, 1UL));
            int numCounts = sig.Count;
            while (Pop(IsRequirement) is { } req) sig.Add(req);
            sig.Reverse(numCounts);
            return sig;
        }

        private enum ConstraintKind { Protocol, BaseClass, SameType, SameShape, Layout, PackMarker, Inverse, ValueMarker }
        private enum ConstrainedTypeKind { Generic, Assoc, CompoundAssoc, Substitution }

        private SwiftNode? DemangleGenericRequirement()
        {
            ConstraintKind ck;
            ConstrainedTypeKind tk;
            SwiftNode? inverseKind = null;
            switch (Next())
            {
                case 'V': ck = ConstraintKind.ValueMarker; tk = ConstrainedTypeKind.Generic; break;
                case 'v': ck = ConstraintKind.PackMarker; tk = ConstrainedTypeKind.Generic; break;
                case 'c': ck = ConstraintKind.BaseClass; tk = ConstrainedTypeKind.Assoc; break;
                case 'C': ck = ConstraintKind.BaseClass; tk = ConstrainedTypeKind.CompoundAssoc; break;
                case 'b': ck = ConstraintKind.BaseClass; tk = ConstrainedTypeKind.Generic; break;
                case 'B': ck = ConstraintKind.BaseClass; tk = ConstrainedTypeKind.Substitution; break;
                case 't': ck = ConstraintKind.SameType; tk = ConstrainedTypeKind.Assoc; break;
                case 'T': ck = ConstraintKind.SameType; tk = ConstrainedTypeKind.CompoundAssoc; break;
                case 's': ck = ConstraintKind.SameType; tk = ConstrainedTypeKind.Generic; break;
                case 'S': ck = ConstraintKind.SameType; tk = ConstrainedTypeKind.Substitution; break;
                case 'm': ck = ConstraintKind.Layout; tk = ConstrainedTypeKind.Assoc; break;
                case 'M': ck = ConstraintKind.Layout; tk = ConstrainedTypeKind.CompoundAssoc; break;
                case 'l': ck = ConstraintKind.Layout; tk = ConstrainedTypeKind.Generic; break;
                case 'L': ck = ConstraintKind.Layout; tk = ConstrainedTypeKind.Substitution; break;
                case 'p': ck = ConstraintKind.Protocol; tk = ConstrainedTypeKind.Assoc; break;
                case 'P': ck = ConstraintKind.Protocol; tk = ConstrainedTypeKind.CompoundAssoc; break;
                case 'Q': ck = ConstraintKind.Protocol; tk = ConstrainedTypeKind.Substitution; break;
                case 'h': ck = ConstraintKind.SameShape; tk = ConstrainedTypeKind.Generic; break;
                case 'i' or 'I' or 'j' or 'J':
                {
                    char c = text[pos - 1];
                    ck = ConstraintKind.Inverse;
                    tk = c switch { 'i' => ConstrainedTypeKind.Generic, 'I' => ConstrainedTypeKind.Substitution, 'j' => ConstrainedTypeKind.Assoc, _ => ConstrainedTypeKind.CompoundAssoc };
                    inverseKind = DemangleIndexAsNode();
                    if (inverseKind == null) return null;
                    break;
                }
                default:
                    ck = ConstraintKind.Protocol;
                    tk = ConstrainedTypeKind.Generic;
                    PushBack();
                    break;
            }
            SwiftNode? constrained = null;
            switch (tk)
            {
                case ConstrainedTypeKind.Generic: constrained = CreateType(DemangleGenericParamIndex()); break;
                case ConstrainedTypeKind.Assoc:
                    constrained = DemangleAssociatedTypeSimple(DemangleGenericParamIndex());
                    AddSubstitution(constrained);
                    break;
                case ConstrainedTypeKind.CompoundAssoc:
                    constrained = DemangleAssociatedTypeCompound(DemangleGenericParamIndex());
                    AddSubstitution(constrained);
                    break;
                case ConstrainedTypeKind.Substitution: constrained = Pop(K.Type); break;
            }
            switch (ck)
            {
                case ConstraintKind.ValueMarker: return With(K.DependentGenericParamValueMarker, constrained, Pop(K.Type));
                case ConstraintKind.PackMarker: return With(K.DependentGenericParamPackMarker, constrained);
                case ConstraintKind.Protocol: return With(K.DependentGenericConformanceRequirement, constrained, PopProtocol());
                case ConstraintKind.Inverse: return With(K.DependentGenericInverseConformanceRequirement, constrained, inverseKind);
                case ConstraintKind.BaseClass: return With(K.DependentGenericConformanceRequirement, constrained, Pop(K.Type));
                case ConstraintKind.SameType: return With(K.DependentGenericSameTypeRequirement, constrained, Pop(K.Type));
                case ConstraintKind.SameShape: return With(K.DependentGenericSameShapeRequirement, constrained, Pop(K.Type));
            }
            char lc = Next();
            SwiftNode? size = null, alignment = null;
            string name;
            switch (lc)
            {
                case 'U' or 'R' or 'N' or 'C' or 'D' or 'T' or 'B': name = lc.ToString(); break;
                case 'E' or 'M':
                    size = DemangleIndexAsNode();
                    if (size == null) return null;
                    alignment = DemangleIndexAsNode();
                    name = lc.ToString();
                    break;
                case 'e' or 'm' or 'S':
                    size = DemangleIndexAsNode();
                    if (size == null) return null;
                    name = lc.ToString();
                    break;
                default: return null;
            }
            var layoutReq = With(K.DependentGenericLayoutRequirement, constrained, N(K.Identifier, name));
            if (size != null) AddChild(layoutReq, size);
            if (alignment != null) AddChild(layoutReq, alignment);
            return layoutReq;
        }

        private SwiftNode? DemangleGenericType()
        {
            var sig = Pop(K.DependentGenericSignature);
            var ty = Pop(K.Type);
            return CreateType(With(K.DependentGenericType, sig, ty));
        }

        private static readonly string[] ValueWitnessCodes =
            ["al", "ca", "ta", "de", "xx", "XX", "Xx", "CP", "Cp", "cp", "Tk", "tk", "pr", "TK", "Cc", "Tt", "tT", "xs", "xg", "ug", "up", "ui", "et", "st"];

        internal static int ValueWitnessKind(string code) => Array.IndexOf(ValueWitnessCodes, code);

        private SwiftNode? DemangleValueWitness()
        {
            char first = Next(), second = Next();
            string code = $"{first}{second}";
            int kind = ValueWitnessKind(code);
            if (kind < 0) return null;
            var vw = N(K.ValueWitness);
            AddChild(vw, N(K.Index, (ulong)kind));
            return AddChild(vw, Pop(K.Type));
        }

        private static bool IsMacroExpansion(K k) => k is K.AccessorAttachedMacroExpansion or K.MemberAttributeAttachedMacroExpansion
            or K.FreestandingMacroExpansion or K.MemberAttachedMacroExpansion or K.PeerAttachedMacroExpansion or K.ConformanceAttachedMacroExpansion
            or K.ExtensionAttachedMacroExpansion or K.MacroExpansionLoc;

        private SwiftNode? DemangleMacroExpansion()
        {
            K kind;
            bool attached = true, freestanding = false;
            switch (Next())
            {
                case 'a': kind = K.AccessorAttachedMacroExpansion; break;
                case 'r': kind = K.MemberAttributeAttachedMacroExpansion; break;
                case 'm': kind = K.MemberAttachedMacroExpansion; break;
                case 'p': kind = K.PeerAttachedMacroExpansion; break;
                case 'c': kind = K.ConformanceAttachedMacroExpansion; break;
                case 'e': kind = K.ExtensionAttachedMacroExpansion; break;
                case 'q': kind = K.PreambleAttachedMacroExpansion; break;
                case 'b': kind = K.BodyAttachedMacroExpansion; break;
                case 'f':
                    kind = K.FreestandingMacroExpansion;
                    attached = false;
                    freestanding = true;
                    break;
                case 'u':
                    kind = K.MacroExpansionUniqueName;
                    attached = false;
                    break;
                case 'X':
                {
                    int line = DemangleIndex();
                    int col = DemangleIndex();
                    var lineNode = N(K.Index, (long)line);
                    var colNode = N(K.Index, (long)col);
                    var buffer = Pop(K.Identifier);
                    var module = Pop(K.Identifier);
                    return With(K.MacroExpansionLoc, module, buffer, lineNode, colNode);
                }
                default: return null;
            }
            var macroName = Pop(K.Identifier);
            var privateDiscriminator = freestanding ? Pop(K.PrivateDeclName) : null;
            var attachedName = attached ? Pop(IsDeclName) : null;
            var context = Pop(IsMacroExpansion) ?? PopContext();
            var discriminator = DemangleIndexAsNode();
            var result = attached && attachedName != null
                ? With(kind, context, attachedName, macroName, discriminator)
                : With(kind, context, macroName, discriminator);
            if (result == null) return null;
            if (privateDiscriminator != null) result.Add(privateDiscriminator);
            return result;
        }

        private SwiftNode? DemangleIntegerType()
        {
            SwiftNode integer;
            if (Peek() == 'n')
            {
                Next();
                integer = N(K.NegativeInteger, (long)-DemangleIndex());
            }
            else integer = N(K.Integer, (long)DemangleIndex());
            return CreateType(integer);
        }
    }

    /// <summary>Function signature specialization parameter kinds: values 0-12, option flags from bit 6.</summary>
    internal enum FuncSigParamKind : uint
    {
        ConstantPropFunction = 0,
        ConstantPropGlobal = 1,
        ConstantPropInteger = 2,
        ConstantPropFloat = 3,
        ConstantPropString = 4,
        ClosureProp = 5,
        BoxToValue = 6,
        BoxToStack = 7,
        InOutToOut = 8,
        ConstantPropKeyPath = 9,
        ConstantPropStruct = 10,
        ClosurePropPreviousArg = 11,
        EscapingClosureProp = 12,
        Dead = 1 << 6,
        OwnedToGuaranteed = 1 << 7,
        SROA = 1 << 8,
        GuaranteedToOwned = 1 << 9,
        ExistentialToGeneric = 1 << 10,
    }
}
