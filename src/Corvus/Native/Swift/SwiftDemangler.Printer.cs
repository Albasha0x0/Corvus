using System.Globalization;
using System.Text;
using K = Corvus.Native.Swift.SwiftNodeKind;

namespace Corvus.Native.Swift;

public static partial class SwiftDemangler
{
    /// <summary>What the printer shows; <see cref="Default"/> is swift-demangle's output (sugared types).</summary>
    internal sealed record PrintOptions
    {
        public static readonly PrintOptions Default = new();
        /// <summary>The runtime library's defaults (no sugar), used for symbols nested in specializations.</summary>
        public static readonly PrintOptions Plain = new() { SynthesizeSugarOnTypes = false };
        public bool SynthesizeSugarOnTypes { get; init; } = true;
        public bool QualifyEntities { get; init; } = true;
        public bool DisplayExtensionContexts { get; init; } = true;
        public bool DisplayUnmangledSuffix { get; init; } = true;
        public bool DisplayModuleNames { get; init; } = true;
        public bool DisplayGenericSpecializations { get; init; } = true;
        public bool DisplayProtocolConformances { get; init; } = true;
        public bool DisplayWhereClauses { get; init; } = true;
        public bool DisplayEntityTypes { get; init; } = true;
        public bool DisplayLocalNameContexts { get; init; } = true;
        public bool ShortenPartialApply { get; init; }
        public bool ShortenThunk { get; init; }
        public bool ShortenValueWitness { get; init; }
        public bool ShowPrivateDiscriminators { get; init; } = true;
        public bool ShowFunctionArgumentTypes { get; init; } = true;
        public bool DisplayDebuggerGeneratedModule { get; init; } = true;
        public bool DisplayStdlibModule { get; init; } = true;
        public bool DisplayObjCModule { get; init; } = true;
        public bool PrintForTypeName { get; init; }
        public bool ShowAsyncResumePartial { get; init; } = true;
        public bool ShowClosureSignature { get; init; } = true;
    }

    /// <summary>The text of <paramref name="root"/>, or null when the tree is malformed for printing.</summary>
    internal static string? Print(SwiftNode root, PrintOptions options)
    {
        var printer = new Printer(options);
        printer.Print(root, 0);
        return printer.Valid ? printer.Text : null;
    }

    private sealed class Printer(PrintOptions options)
    {
        private const int MaxDepth = 768;
        private readonly StringBuilder sb = new();
        private PrintOptions opts = options;
        private bool specializationPrefixPrinted;

        public bool Valid { get; private set; } = true;
        public string Text => sb.ToString();

        private Printer Out(string? s)
        {
            sb.Append(s);
            if (sb.Length > MaxOutput) throw new TooComplex();
            return this;
        }

        private Printer Out(char c)
        {
            sb.Append(c);
            return this;
        }

        private Printer Out(ulong n) => Out(n.ToString(CultureInfo.InvariantCulture));
        private Printer Out(long n) => Out(n.ToString(CultureInfo.InvariantCulture));
        private Printer Hex(ulong n) => Out(n.ToString("X", CultureInfo.InvariantCulture));

        private void SetInvalid() => Valid = false;

        private void PrintChildren(SwiftNode? node, int depth, string? sep = null)
        {
            if (node == null) return;
            var children = node.Children;
            for (int i = 0; i < children.Count; i++)
            {
                Print(children[i], depth + 1);
                if (sep != null && i + 1 < children.Count) Out(sep);
            }
        }

        private static SwiftNode? ChildIf(SwiftNode node, K kind)
        {
            foreach (var c in node.Children)
                if (c.Kind == kind) return c;
            return null;
        }

        private void PrintBoundGenericNoSugar(SwiftNode node, int depth)
        {
            if (node.Count < 2) return;
            Print(node[0], depth + 1);
            Out("<");
            PrintChildren(node[1], depth, ", ");
            Out(">");
        }

        private static bool IsExistentialType(SwiftNode n) => n.Kind is K.ExistentialMetatype or K.ProtocolList or K.ProtocolListWithClass or K.ProtocolListWithAnyObject;

        private void PrintOptionalIndex(SwiftNode node)
        {
            if (node.HasIndex) Out("#").Out(node.Index).Out(" ");
        }

        private bool PrintContext(SwiftNode context)
        {
            if (!opts.QualifyEntities) return false;
            if (context.Kind == K.Module)
            {
                if (context.Text == "Swift") return opts.DisplayStdlibModule;
                if (context.Text == "__C") return opts.DisplayObjCModule;
                if (context.Text!.StartsWith("__lldb_expr_", StringComparison.Ordinal)) return opts.DisplayDebuggerGeneratedModule;
            }
            return true;
        }

        private static bool IsSimpleType(SwiftNode n)
        {
            switch (n.Kind)
            {
                case K.AssociatedType or K.AssociatedTypeRef or K.BoundGenericClass or K.BoundGenericEnum or K.BoundGenericStructure or K.BoundGenericProtocol
                    or K.BoundGenericOtherNominalType or K.BoundGenericTypeAlias or K.BoundGenericFunction or K.BuiltinTypeName or K.BuiltinTupleType
                    or K.BuiltinFixedArray or K.BuiltinBorrow or K.Class or K.DependentGenericType or K.DependentMemberType or K.DependentGenericParamType
                    or K.DynamicSelf or K.Enum or K.ErrorType or K.ExistentialMetatype or K.Metatype or K.MetatypeRepresentation or K.Module or K.Tuple
                    or K.Pack or K.SILPackDirect or K.SILPackIndirect or K.ConstrainedExistentialRequirementList or K.ConstrainedExistentialSelf or K.Protocol
                    or K.ProtocolSymbolicReference or K.ReturnType or K.SILBoxType or K.SILBoxTypeWithLayout or K.Structure or K.OtherNominalType
                    or K.TupleElementName or K.TypeAlias or K.TypeList or K.LabelList or K.TypeSymbolicReference or K.SugaredOptional or K.SugaredArray
                    or K.SugaredInlineArray or K.SugaredDictionary or K.SugaredParen or K.Integer or K.NegativeInteger:
                    return true;
                case K.Type: return IsSimpleType(n[0]!);
                case K.ProtocolList: return n[0]!.Count <= 1;
                case K.ProtocolListWithAnyObject: return n[0]![0]!.Count == 0;
                default: return false;
            }
        }

        private void PrintWithParens(SwiftNode type, int depth)
        {
            bool parens = !IsSimpleType(type);
            if (parens) Out("(");
            Print(type, depth + 1);
            if (parens) Out(")");
        }

        private enum Sugar { None, Optional, ImplicitlyUnwrappedOptional, Array, Dictionary }

        private static bool IsSwiftModule(SwiftNode? n) => n is { Kind: K.Module, Text: "Swift" };
        private static bool IsIdentifier(SwiftNode? n, string desired) => n != null && n.Kind == K.Identifier && n.Text == desired;

        private static Sugar FindSugar(SwiftNode node)
        {
            if (node.Count == 1 && node.Kind == K.Type) return FindSugar(node[0]!);
            if (node.Count != 2 || node.Kind is not (K.BoundGenericEnum or K.BoundGenericStructure)) return Sugar.None;
            var unbound = node[0]![0]!;
            var args = node[1]!;
            if (node.Kind == K.BoundGenericEnum)
            {
                if (IsIdentifier(unbound[1], "Optional") && args.Count == 1 && IsSwiftModule(unbound[0])) return Sugar.Optional;
                if (IsIdentifier(unbound[1], "ImplicitlyUnwrappedOptional") && args.Count == 1 && IsSwiftModule(unbound[0])) return Sugar.ImplicitlyUnwrappedOptional;
                return Sugar.None;
            }
            if (IsIdentifier(unbound[1], "Array") && args.Count == 1 && IsSwiftModule(unbound[0])) return Sugar.Array;
            if (IsIdentifier(unbound[1], "Dictionary") && args.Count == 2 && IsSwiftModule(unbound[0])) return Sugar.Dictionary;
            return Sugar.None;
        }

        private void PrintBoundGeneric(SwiftNode node, int depth)
        {
            if (node.Count < 2) return;
            if (node.Count != 2 || !opts.SynthesizeSugarOnTypes || node.Kind == K.BoundGenericClass)
            {
                PrintBoundGenericNoSugar(node, depth);
                return;
            }
            if (node.Kind == K.BoundGenericProtocol)
            {
                PrintChildren(node[1], depth);
                Out(" as ");
                Print(node[0], depth + 1);
                return;
            }
            var sugar = FindSugar(node);
            switch (sugar)
            {
                case Sugar.None: PrintBoundGenericNoSugar(node, depth); break;
                case Sugar.Optional or Sugar.ImplicitlyUnwrappedOptional:
                    PrintWithParens(node[1]![0]!, depth);
                    Out(sugar == Sugar.Optional ? "?" : "!");
                    break;
                case Sugar.Array:
                    Out("[");
                    Print(node[1]![0], depth + 1);
                    Out("]");
                    break;
                case Sugar.Dictionary:
                    Out("[");
                    Print(node[1]![0], depth + 1);
                    Out(" : ");
                    Print(node[1]![1], depth + 1);
                    Out("]");
                    break;
            }
        }

        private void PrintFunctionParameters(SwiftNode? labelList, SwiftNode parameterType, int depth, bool showTypes)
        {
            if (parameterType.Kind is not (K.ArgumentTuple or K.YieldTypes))
            {
                SetInvalid();
                return;
            }
            var parameters = parameterType.First!.First!;
            if (parameters.Kind != K.Tuple)
            {
                if (showTypes)
                {
                    Out('(');
                    Print(parameters, depth + 1);
                    Out(')');
                }
                else Out("(_:)");
                return;
            }
            bool hasLabels = labelList != null && labelList.Count > 0;
            Out('(');
            var children = parameters.Children;
            for (int i = 0; i < children.Count; i++)
            {
                var param = children[i];
                if (hasLabels)
                {
                    var label = labelList![i]!;
                    Out(label.Kind == K.Identifier ? label.Text : "_").Out(':');
                }
                else if (!showTypes)
                {
                    if (ChildIf(param, K.TupleElementName) is { } name) Out(name.Text).Out(":");
                    else Out("_:");
                }
                if (hasLabels && showTypes) Out(' ');
                if (showTypes) Print(param, depth + 1);
                if (i + 1 < children.Count && showTypes) Out(", ");
            }
            Out(')');
        }

        private void PrintFunctionType(SwiftNode? labelList, SwiftNode node, int depth)
        {
            if (node.Count < 2)
            {
                SetInvalid();
                return;
            }
            void ConventionWithCType(string convention)
            {
                Out("@convention(").Out(convention);
                if (node.First!.Kind == K.ClangType)
                {
                    Out(", mangledCType: \"");
                    Print(node.First, depth + 1);
                    Out('"');
                }
                Out(") ");
            }
            switch (node.Kind)
            {
                case K.FunctionType or K.UncurriedFunctionType or K.NoEscapeFunctionType: break;
                case K.CalledOnceFunctionType: Out("@called(exactlyOnce) "); break;
                case K.CalledAtMostOnceFunctionType: Out("@called(atMostOnce) "); break;
                case K.AutoClosureType or K.EscapingAutoClosureType: Out("@autoclosure "); break;
                case K.ThinFunctionType: Out("@convention(thin) "); break;
                case K.CFunctionPointer: ConventionWithCType("c"); break;
                case K.EscapingObjCBlock:
                    Out("@escaping ");
                    ConventionWithCType("block");
                    break;
                case K.ObjCBlock: ConventionWithCType("block"); break;
            }
            int argIndex = node.Count - 2;
            int start = 0;
            bool sendable = false, isAsync = false, sendingResult = false;
            char diffKind = '\0';
            if (node[start]!.Kind == K.ClangType) start++;
            if (node[start]!.Kind == K.SendingResultFunctionType)
            {
                start++;
                sendingResult = true;
            }
            if (node[start]!.Kind == K.IsolatedAnyFunctionType)
            {
                Print(node[start], depth + 1);
                start++;
            }
            SwiftNode? nonIsolatedCaller = null;
            if (node[start]!.Kind == K.NonIsolatedCallerFunctionType)
            {
                nonIsolatedCaller = node[start];
                start++;
            }
            if (node[start]!.Kind == K.GlobalActorFunctionType)
            {
                Print(node[start], depth + 1);
                start++;
            }
            if (node[start]!.Kind == K.DifferentiableFunctionType)
            {
                diffKind = (char)node[start]!.Index;
                start++;
            }
            SwiftNode? thrown = null;
            if (node[start]!.Kind is K.ThrowsAnnotation or K.TypedThrowsAnnotation)
            {
                thrown = node[start];
                start++;
            }
            if (node[start]!.Kind == K.ConcurrentFunctionType)
            {
                start++;
                sendable = true;
            }
            if (node[start]!.Kind == K.AsyncAnnotation)
            {
                start++;
                isAsync = true;
            }
            switch (diffKind)
            {
                case 'f': Out("@differentiable(_forward) "); break;
                case 'r': Out("@differentiable(reverse) "); break;
                case 'l': Out("@differentiable(_linear) "); break;
                case 'd': Out("@differentiable "); break;
            }
            if (nonIsolatedCaller != null) Print(nonIsolatedCaller, depth + 1);
            if (sendable) Out("@Sendable ");
            PrintFunctionParameters(labelList, node[argIndex]!, depth, opts.ShowFunctionArgumentTypes);
            if (!opts.ShowFunctionArgumentTypes) return;
            if (isAsync) Out(" async");
            if (thrown != null) Print(thrown, depth + 1);
            Out(" -> ");
            if (sendingResult) Out("sending ");
            Print(node[argIndex + 1], depth + 1);
        }

        private void PrintImplFunctionType(SwiftNode fn, int depth)
        {
            SwiftNode? patternSubs = null, invocationSubs = null, sendingResult = null;
            int state = 0; // attrs, inputs, results
            void TransitionTo(int next)
            {
                for (; state != next; state++)
                {
                    if (state == 0)
                    {
                        if (patternSubs != null)
                        {
                            Out("@substituted ");
                            Print(patternSubs[0], depth + 1);
                            Out(' ');
                        }
                        Out('(');
                    }
                    else if (state == 1)
                    {
                        Out(") -> ");
                        if (sendingResult != null)
                        {
                            Print(sendingResult, depth + 1);
                            Out(" ");
                        }
                        Out("(");
                    }
                }
            }
            foreach (var child in fn.Children)
            {
                if (child.Kind == K.ImplParameter)
                {
                    if (state == 1) Out(", ");
                    TransitionTo(1);
                    Print(child, depth + 1);
                }
                else if (child.Kind is K.ImplResult or K.ImplYield or K.ImplErrorResult)
                {
                    if (state == 2) Out(", ");
                    TransitionTo(2);
                    Print(child, depth + 1);
                }
                else if (child.Kind == K.ImplPatternSubstitutions) patternSubs = child;
                else if (child.Kind == K.ImplInvocationSubstitutions) invocationSubs = child;
                else if (child.Kind == K.ImplSendingResult) sendingResult = child;
                else
                {
                    Print(child, depth + 1);
                    Out(' ');
                }
            }
            TransitionTo(2);
            Out(')');
            if (patternSubs != null)
            {
                Out(" for <");
                PrintChildren(patternSubs[1], depth);
                Out('>');
            }
            if (invocationSubs != null)
            {
                Out(" for <");
                PrintChildren(invocationSubs[0], depth);
                Out('>');
            }
        }

        private void PrintGenericSignature(SwiftNode node, int depth)
        {
            Out('<');
            int numChildren = node.Count;
            int numParams = 0;
            while (numParams < numChildren && node[numParams]!.Kind == K.DependentGenericParamCount) numParams++;
            int firstReq = numParams;
            for (; firstReq < numChildren; firstReq++)
            {
                var child = node[firstReq]!;
                if (child.Kind == K.Type) child = child[0]!;
                if (child.Kind is not (K.DependentGenericParamPackMarker or K.DependentGenericParamValueMarker)) break;
            }
            bool IsPack(ulong d, ulong index)
            {
                for (int i = numParams; i < firstReq; i++)
                {
                    var child = node[i]!;
                    if (child.Kind != K.DependentGenericParamPackMarker) continue;
                    child = child[0]!;
                    if (child.Kind != K.Type) continue;
                    child = child[0]!;
                    if (child.Kind != K.DependentGenericParamType) continue;
                    if (index == child[0]!.Index && d == child[1]!.Index) return true;
                }
                return false;
            }
            (bool, SwiftNode?) Value(ulong d, ulong index)
            {
                for (int i = numParams; i < firstReq; i++)
                {
                    var child = node[i]!;
                    if (child.Kind != K.DependentGenericParamValueMarker) continue;
                    child = child[0]!;
                    if (child.Kind != K.Type) continue;
                    var param = child[0]!;
                    var type = child[1];
                    if (param.Kind != K.DependentGenericParamType) continue;
                    if (index == param[0]!.Index && d == param[1]!.Index) return (true, type);
                }
                return (false, null);
            }
            for (int gpDepth = 0; gpDepth < numParams; gpDepth++)
            {
                if (gpDepth != 0) Out("><");
                ulong count = node[gpDepth]!.Index;
                for (ulong index = 0; index < count; index++)
                {
                    if (index != 0) Out(", ");
                    if (index >= 128)
                    {
                        Out("...");
                        break;
                    }
                    if (IsPack((ulong)gpDepth, index)) Out("each ");
                    var value = Value((ulong)gpDepth, index);
                    if (value.Item1) Out("let ");
                    Out(GenericParameterName((ulong)gpDepth, index));
                    if (value.Item2 != null)
                    {
                        Out(": ");
                        Print(value.Item2, depth + 1);
                    }
                }
            }
            if (firstReq != numChildren && opts.DisplayWhereClauses)
            {
                Out(" where ");
                for (int i = firstReq; i < numChildren; i++)
                {
                    if (i > firstReq) Out(", ");
                    Print(node[i], depth + 1);
                }
            }
            Out('>');
        }

        private void PrintFunctionSigSpecializationParams(SwiftNode node, int depth)
        {
            int idx = 0, argIdx = 0, end = node.Count;
            while (idx < end)
            {
                var child = node[idx]!;
                if (!child.HasIndex) return;
                var k = (FuncSigParamKind)child.Index;
                switch (k)
                {
                    case FuncSigParamKind.BoxToValue or FuncSigParamKind.BoxToStack or FuncSigParamKind.InOutToOut:
                        Print(node[idx++], depth + 1);
                        break;
                    case FuncSigParamKind.ConstantPropFunction or FuncSigParamKind.ConstantPropGlobal or FuncSigParamKind.ConstantPropStruct:
                        Out("[");
                        Print(node[idx++], depth + 1);
                        Out(" : ");
                        PrintNextParamChildNode(node, ref argIdx, k, depth);
                        Out("]");
                        break;
                    case FuncSigParamKind.ConstantPropInteger or FuncSigParamKind.ConstantPropFloat:
                        if (idx + 2 > end) return;
                        Out("[");
                        Print(node[idx++], depth + 1);
                        Out(" : ");
                        Print(node[idx++], depth + 1);
                        Out("]");
                        break;
                    case FuncSigParamKind.ConstantPropString:
                        if (idx + 2 > end) return;
                        Out("[");
                        Print(node[idx++], depth + 1);
                        Out(" : ");
                        Print(node[idx++], depth + 1);
                        Out("'");
                        PrintNextParamChildNode(node, ref argIdx, k, depth);
                        Out("'");
                        Out("]");
                        break;
                    case FuncSigParamKind.ConstantPropKeyPath:
                        Out("[");
                        Print(node[idx++], depth + 1);
                        Out(" : ");
                        PrintNextParamChildNode(node, ref argIdx, k, depth);
                        Out("<");
                        PrintNextParamChildNode(node, ref argIdx, k, depth);
                        Out(",");
                        PrintNextParamChildNode(node, ref argIdx, k, depth);
                        Out(">]");
                        break;
                    case FuncSigParamKind.ClosureProp or FuncSigParamKind.EscapingClosureProp:
                        if (idx + 2 > end) return;
                        Out("[");
                        Print(node[idx++], depth + 1);
                        Out(" : ");
                        Print(node[idx++], depth + 1);
                        Out(", Argument Types : [");
                        for (int e = node.Count; idx < e;)
                        {
                            var c = node[idx]!;
                            if (c.Kind != K.Type) break;
                            Print(c, depth + 1);
                            idx++;
                            if (idx < e && node[idx]!.HasText) Out(", ");
                        }
                        Out("]");
                        break;
                    case FuncSigParamKind.ClosurePropPreviousArg:
                        if (idx + 2 > end) return;
                        Out("[");
                        Print(node[idx++], depth + 1);
                        Out(" ");
                        Print(node[idx++], depth + 1);
                        Out("]");
                        break;
                    default:
                        Print(node[idx++], depth + 1);
                        break;
                }
            }
        }

        private void PrintNextParamChildNode(SwiftNode nd, ref int idx, FuncSigParamKind kind, int depth)
        {
            while (idx < nd.Count)
            {
                var child = nd[idx++]!;
                if (child.Kind is K.FunctionSignatureSpecializationParamKind or K.FunctionSignatureSpecializationParamPayload) continue;
                switch (kind)
                {
                    case FuncSigParamKind.ConstantPropInteger or FuncSigParamKind.ConstantPropFloat:
                        if (!child.HasText) return;
                        Out(DemangleSymbolOrSelf(child.Text!));
                        break;
                    case FuncSigParamKind.ConstantPropString:
                        if (child.HasText && child.Text!.Length > 0 && child.Text[0] == '_')
                        {
                            Out(child.Text[1..]);
                            return;
                        }
                        Print(child, depth + 1);
                        break;
                    case FuncSigParamKind.ConstantPropFunction or FuncSigParamKind.ConstantPropGlobal:
                        Out(DemangleSymbolOrSelf(child.Text ?? ""));
                        break;
                    default:
                        Print(child, depth + 1);
                        break;
                }
                return;
            }
        }

        /// <summary>A nested symbol's demangling, or the text itself.</summary>
        private static string DemangleSymbolOrSelf(string text)
        {
            if (text.Length == 0) return text;
            var root = (PrefixLength(text) > 0 || AsyncMainLength(text) > 0) ? new Parser(text, null).DemangleSymbol() : new OldParser(text).DemangleTopLevel();
            if (root == null) return text;
            return SwiftDemangler.Print(root, PrintOptions.Plain) is { Length: > 0 } s ? s : text;
        }

        private void PrintSpecializationPrefix(SwiftNode node, string description, int depth, string paramPrefix = "")
        {
            if (!opts.DisplayGenericSpecializations)
            {
                if (!specializationPrefixPrinted)
                {
                    Out("specialized ");
                    specializationPrefixPrinted = true;
                }
                return;
            }
            if (node.First!.Kind == K.RepresentationChanged)
            {
                Out("representation changed of ");
                return;
            }
            Out(description).Out(" <");
            string separator = "";
            int argNum = 0;
            foreach (var child in node.Children)
            {
                switch (child.Kind)
                {
                    case K.SpecializationPassID or K.DroppedArgument: break;
                    case K.IsSerialized:
                        Out(separator);
                        separator = ", ";
                        Print(child, depth + 1);
                        break;
                    default:
                        if (child.HasChildren)
                        {
                            Out(separator).Out(paramPrefix);
                            separator = ", ";
                            switch (child.Kind)
                            {
                                case K.FunctionSignatureSpecializationParam:
                                    Out("Arg[").Out((long)argNum).Out("] = ");
                                    PrintFunctionSigSpecializationParams(child, depth);
                                    break;
                                case K.FunctionSignatureSpecializationReturn:
                                    Out("Return = ");
                                    PrintFunctionSigSpecializationParams(child, depth);
                                    break;
                                default:
                                    Print(child, depth + 1);
                                    break;
                            }
                        }
                        argNum++;
                        break;
                }
            }
            Out("> of ");
        }

        private static bool NeedSpaceBeforeType(SwiftNode type) => type.Kind switch
        {
            K.Type => NeedSpaceBeforeType(type.First!),
            K.FunctionType or K.NoEscapeFunctionType or K.UncurriedFunctionType or K.CalledOnceFunctionType or K.CalledAtMostOnceFunctionType
                or K.DependentGenericType => false,
            _ => true,
        };

        private enum TypePrinting { NoType, WithColon, FunctionStyle }

        private const string InvertibleCopyable = "Copyable", InvertibleEscapable = "Escapable", InvertibleDeinitable = "Deinitable";

        private static readonly string[] ValueWitnessNames =
        [
            "allocateBuffer", "assignWithCopy", "assignWithTake", "deallocateBuffer", "destroy", "destroyBuffer", "destroyArray",
            "initializeBufferWithCopyOfBuffer", "initializeBufferWithCopy", "initializeWithCopy", "initializeBufferWithTake", "initializeWithTake",
            "projectBuffer", "initializeBufferWithTakeOfBuffer", "initializeArrayWithCopy", "initializeArrayWithTakeFrontToBack",
            "initializeArrayWithTakeBackToFront", "storeExtraInhabitant", "getExtraInhabitantIndex", "getEnumTag", "destructiveProjectEnumData",
            "destructiveInjectEnumTag", "getEnumTagSinglePayload", "storeEnumTagSinglePayload",
        ];

        public SwiftNode? Print(SwiftNode? node, int depth, bool asPrefixContext = false)
        {
            if (depth > MaxDepth)
            {
                Out("<<too complex>>");
                return null;
            }
            if (node == null)
            {
                Out("<null node pointer>");
                return null;
            }
            CheckStack();
            var kind = node.Kind;
            switch (kind)
            {
                case K.Static:
                    Out("static ");
                    Print(node[0], depth + 1);
                    return null;
                case K.AsyncRemoved: return Prefixed("async demotion of ", node, depth);
                case K.RepresentationChanged: return Prefixed("representation changed of ", node, depth);
                case K.CurryThunk: return Prefixed("curry thunk of ", node, depth);
                case K.SILThunkIdentity: return Prefixed("identity thunk of ", node, depth);
                case K.DispatchThunk: return Prefixed("dispatch thunk of ", node, depth);
                case K.MethodDescriptor: return Prefixed("method descriptor for ", node, depth);
                case K.MethodLookupFunction: return Prefixed("method lookup function for ", node, depth);
                case K.ObjCMetadataUpdateFunction: return Prefixed("ObjC metadata update function for ", node, depth);
                case K.ObjCResilientClassStub: return Prefixed("ObjC resilient class stub for ", node, depth);
                case K.FullObjCResilientClassStub: return Prefixed("full ObjC resilient class stub for ", node, depth);
                case K.OutlinedBridgedMethod:
                    Out("outlined bridged method (").Out(node.Text).Out(") of ");
                    return null;
                case K.OutlinedCopy or K.OutlinedConsume:
                    Out(kind == K.OutlinedCopy ? "outlined copy of " : "outlined consume of ");
                    Print(node[0], depth + 1);
                    if (node.Count > 1) Print(node[1], depth + 1);
                    return null;
                case K.OutlinedRetain: return Prefixed("outlined retain of ", node, depth);
                case K.OutlinedRelease: return Prefixed("outlined release of ", node, depth);
                case K.OutlinedInitializeWithTake or K.OutlinedInitializeWithTakeNoValueWitness: return Prefixed("outlined init with take of ", node, depth);
                case K.OutlinedInitializeWithCopy or K.OutlinedInitializeWithCopyNoValueWitness: return Prefixed("outlined init with copy of ", node, depth);
                case K.OutlinedAssignWithTake or K.OutlinedAssignWithTakeNoValueWitness: return Prefixed("outlined assign with take of ", node, depth);
                case K.OutlinedAssignWithCopy or K.OutlinedAssignWithCopyNoValueWitness: return Prefixed("outlined assign with copy of ", node, depth);
                case K.OutlinedDestroy or K.OutlinedDestroyNoValueWitness: return Prefixed("outlined destroy of ", node, depth);
                case K.OutlinedEnumProjectDataForLoad: return Prefixed("outlined enum project data for load of ", node, depth);
                case K.OutlinedEnumTagStore: return Prefixed("outlined enum tag store of ", node, depth);
                case K.OutlinedEnumGetTag: return Prefixed("outlined enum get tag of ", node, depth);
                case K.OutlinedVariable:
                    Out("outlined variable #").Out(node.Index).Out(" of ");
                    return null;
                case K.OutlinedReadOnlyObject:
                    Out("outlined read-only object #").Out(node.Index).Out(" of ");
                    return null;
                case K.Directness:
                    Out(node.Index == 0 ? "direct" : "indirect").Out(" ");
                    return null;
                case K.AnonymousContext:
                    if (opts.QualifyEntities && opts.DisplayExtensionContexts)
                    {
                        Print(node[1], depth + 1);
                        Out(".(unknown context at ");
                        Print(node[0], depth + 1);
                        Out(")");
                        if (node.Count >= 3 && node[2]!.Count > 0)
                        {
                            Out('<');
                            Print(node[2], depth + 1);
                            Out('>');
                        }
                    }
                    return null;
                case K.Extension:
                    if (opts.QualifyEntities && opts.DisplayExtensionContexts)
                    {
                        Out("(extension in ");
                        Print(node[0], depth + 1, true);
                        Out("):");
                    }
                    Print(node[1], depth + 1);
                    if (node.Count == 3 && !opts.PrintForTypeName) Print(node[2], depth + 1);
                    return null;
                case K.Variable: return PrintEntity(node, depth, asPrefixContext, TypePrinting.WithColon, true);
                case K.Function or K.BoundGenericFunction: return PrintEntity(node, depth, asPrefixContext, TypePrinting.FunctionStyle, true);
                case K.Subscript: return PrintEntity(node, depth, asPrefixContext, TypePrinting.FunctionStyle, false, "", -1, "subscript");
                case K.Macro: return PrintEntity(node, depth, asPrefixContext, node.Count == 3 ? TypePrinting.WithColon : TypePrinting.FunctionStyle, true);
                case K.AccessorAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "accessor");
                case K.MemberAttributeAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "memberAttribute");
                case K.MemberAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "member");
                case K.PeerAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "peer");
                case K.ConformanceAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "conformance");
                case K.ExtensionAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "extension");
                case K.PreambleAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "preamble");
                case K.BodyAttachedMacroExpansion: return AttachedMacro(node, depth, asPrefixContext, "body");
                case K.FreestandingMacroExpansion:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, true, "freestanding macro expansion #", (int)node[2]!.Index + 1);
                case K.MacroExpansionLoc:
                    if (node.Count > 0)
                    {
                        Out("module ");
                        Print(node[0], depth + 1);
                    }
                    if (node.Count > 1)
                    {
                        Out(" file ");
                        Print(node[1], depth + 1);
                    }
                    if (node.Count > 2)
                    {
                        Out(" line ");
                        Print(node[2], depth + 1);
                    }
                    if (node.Count > 3)
                    {
                        Out(" column ");
                        Print(node[3], depth + 1);
                    }
                    return null;
                case K.MacroExpansionUniqueName:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, true, "unique name #", (int)node[2]!.Index + 1);
                case K.GenericTypeParamDecl: return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, true);
                case K.ExplicitClosure:
                    return PrintEntity(node, depth, asPrefixContext, opts.ShowFunctionArgumentTypes ? TypePrinting.FunctionStyle : TypePrinting.NoType,
                        false, "closure #", (int)node[1]!.Index + 1);
                case K.ImplicitClosure:
                    return PrintEntity(node, depth, asPrefixContext, opts.ShowFunctionArgumentTypes ? TypePrinting.FunctionStyle : TypePrinting.NoType,
                        false, "implicit closure #", (int)node[1]!.Index + 1);
                case K.Global:
                    PrintChildren(node, depth);
                    return null;
                case K.Suffix:
                    if (opts.DisplayUnmangledSuffix) Out(" with unmangled suffix ").Out(Quoted(node.Text!));
                    return null;
                case K.Initializer: return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "variable initialization expression");
                case K.PropertyWrapperBackingInitializer:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "property wrapper backing initializer");
                case K.PropertyWrappedFieldInitAccessor:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "property wrapped field init accessor");
                case K.PropertyWrapperInitFromProjectedValue:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "property wrapper init from projected value");
                case K.DefaultArgumentInitializer:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "default argument ", (int)node[1]!.Index);
                case K.DeclContext or K.Type:
                    Print(node[0], depth + 1);
                    return null;
                case K.TypeMangling:
                    if (node[0]!.Kind == K.LabelList) PrintFunctionType(node[0], node[1]!.First!, depth);
                    else Print(node[0], depth + 1);
                    return null;
                case K.Class or K.Structure or K.Enum or K.Protocol or K.TypeAlias or K.OtherNominalType:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, true);
                case K.LocalDeclName:
                    Print(node[1], depth + 1);
                    if (opts.DisplayLocalNameContexts) Out(" #").Out(node[0]!.Index + 1);
                    return null;
                case K.PrivateDeclName:
                    if (node.Count > 1)
                    {
                        if (opts.ShowPrivateDiscriminators) Out('(');
                        Print(node[1], depth + 1);
                        if (opts.ShowPrivateDiscriminators) Out(" in ").Out(node[0]!.Text).Out(')');
                    }
                    else if (opts.ShowPrivateDiscriminators) Out("(in ").Out(node[0]!.Text).Out(')');
                    return null;
                case K.RelatedEntityDeclName:
                    Out("related decl '").Out(node.First!.Text).Out("' for ");
                    Print(node[1], depth + 1);
                    return null;
                case K.Module:
                    if (opts.DisplayModuleNames) Out(node.Text);
                    return null;
                case K.Identifier or K.ClangType or K.BuiltinTypeName or K.MetatypeRepresentation or K.ImplConvention or K.ImplFunctionAttribute:
                    Out(node.Text);
                    return null;
                case K.Index or K.Number or K.SpecializationPassID or K.Integer:
                    Out(node.Index);
                    return null;
                case K.UnknownIndex:
                    Out("unknown index");
                    return null;
                case K.FunctionType or K.UncurriedFunctionType or K.NoEscapeFunctionType or K.CalledOnceFunctionType or K.CalledAtMostOnceFunctionType
                    or K.AutoClosureType or K.EscapingAutoClosureType or K.ThinFunctionType or K.CFunctionPointer or K.ObjCBlock or K.EscapingObjCBlock:
                    PrintFunctionType(null, node, depth);
                    return null;
                case K.ArgumentTuple or K.YieldTypes:
                    PrintFunctionParameters(null, node, depth, opts.ShowFunctionArgumentTypes);
                    return null;
                case K.Tuple:
                    Out("(");
                    PrintChildren(node, depth, ", ");
                    Out(")");
                    return null;
                case K.TupleElement:
                {
                    if (ChildIf(node, K.TupleElementName) is { } label) Out(label.Text).Out(": ");
                    var type = ChildIf(node, K.Type);
                    Print(type, depth + 1);
                    if (ChildIf(node, K.VariadicMarker) != null) Out("...");
                    return null;
                }
                case K.TupleElementName:
                    Out(node.Text).Out(": ");
                    return null;
                case K.Pack:
                    Out("Pack{");
                    PrintChildren(node, depth, ", ");
                    Out("}");
                    return null;
                case K.SILPackDirect or K.SILPackIndirect:
                    Out(kind == K.SILPackDirect ? "@direct" : "@indirect").Out(" Pack{");
                    PrintChildren(node, depth, ", ");
                    Out("}");
                    return null;
                case K.PackExpansion:
                    Out("repeat ");
                    Print(node[0], depth + 1);
                    return null;
                case K.PackElement:
                    Out("/* level: ").Out(node[1]!.Index).Out(" */ ").Out("each ");
                    Print(node[0], depth + 1);
                    return null;
                case K.ReturnType:
                    if (node.Count == 0) Out(node.Text);
                    else PrintChildren(node, depth);
                    return null;
                case K.RetroactiveConformance:
                    if (node.Count != 2) return null;
                    Out("retroactive @ ");
                    Print(node[0], depth + 1);
                    Print(node[1], depth + 1);
                    return null;
                case K.Weak: return Prefixed("weak ", node, depth);
                case K.Unowned: return Prefixed("unowned ", node, depth);
                case K.Unmanaged: return Prefixed("unowned(unsafe) ", node, depth);
                case K.InOut: return Prefixed("inout ", node, depth);
                case K.Isolated: return Prefixed("isolated ", node, depth);
                case K.Sending: return Prefixed("sending ", node, depth);
                case K.CompileTimeLiteral: return Prefixed("_const ", node, depth);
                case K.ConstValue: return Prefixed("@const ", node, depth);
                case K.Shared: return Prefixed("__shared ", node, depth);
                case K.Owned: return Prefixed("__owned ", node, depth);
                case K.NoDerivative: return Prefixed("@noDerivative ", node, depth);
                case K.NonObjCAttribute:
                    Out("@nonobjc ");
                    return null;
                case K.ObjCAttribute:
                    Out("@objc ");
                    return null;
                case K.DirectMethodReferenceAttribute:
                    Out("super ");
                    return null;
                case K.DynamicAttribute:
                    Out("dynamic ");
                    return null;
                case K.VTableAttribute:
                    Out("override ");
                    return null;
                case K.FunctionSignatureSpecialization:
                    PrintSpecializationPrefix(node, "function signature specialization", depth);
                    return null;
                case K.GenericPartialSpecialization:
                    PrintSpecializationPrefix(node, "generic partial specialization", depth, "Signature = ");
                    return null;
                case K.GenericPartialSpecializationNotReAbstracted:
                    PrintSpecializationPrefix(node, "generic not-reabstracted partial specialization", depth, "Signature = ");
                    return null;
                case K.GenericSpecialization or K.GenericSpecializationInResilienceDomain:
                    PrintSpecializationPrefix(node, "generic specialization", depth);
                    return null;
                case K.GenericSpecializationPrespecialized:
                    PrintSpecializationPrefix(node, "generic pre-specialization", depth);
                    return null;
                case K.GenericSpecializationNotReAbstracted:
                    PrintSpecializationPrefix(node, "generic not re-abstracted specialization", depth);
                    return null;
                case K.InlinedGenericFunction:
                    PrintSpecializationPrefix(node, "inlined generic function", depth);
                    return null;
                case K.IsSerialized:
                    Out("serialized");
                    return null;
                case K.DroppedArgument:
                    Out("param").Out(node.Index).Out("-removed");
                    return null;
                case K.GenericSpecializationParam:
                    Print(node[0], depth + 1);
                    for (int i = 1; i < node.Count; i++)
                    {
                        Out(i == 1 ? " with " : " and ");
                        Print(node[i], depth + 1);
                    }
                    return null;
                case K.FunctionSignatureSpecializationReturn or K.FunctionSignatureSpecializationParam:
                    SetInvalid();
                    return null;
                case K.FunctionSignatureSpecializationParamPayload:
                    if (node.HasText) Out(DemangleSymbolOrSelf(node.Text!));
                    else if (node.HasIndex) Out(node.Index);
                    return null;
                case K.FunctionSignatureSpecializationParamKind:
                    PrintParamKind(node.Index);
                    return null;
                case K.BuiltinTupleType:
                    Out("Builtin.TheTupleType");
                    return null;
                case K.BuiltinFixedArray:
                    Out("Builtin.FixedArray<");
                    Print(node[0], depth + 1);
                    Out(", ");
                    Print(node[1], depth + 1);
                    Out(">");
                    return null;
                case K.BuiltinBorrow:
                    Out("Builtin.Borrow<");
                    Print(node[0], depth + 1);
                    Out(">");
                    return null;
                case K.InfixOperator:
                    Out(node.Text).Out(" infix");
                    return null;
                case K.PrefixOperator:
                    Out(node.Text).Out(" prefix");
                    return null;
                case K.PostfixOperator:
                    Out(node.Text).Out(" postfix");
                    return null;
                case K.LazyProtocolWitnessTableAccessor or K.LazyProtocolWitnessTableCacheVariable:
                    Out(kind == K.LazyProtocolWitnessTableAccessor ? "lazy protocol witness table accessor for type " : "lazy protocol witness table cache variable for type ");
                    Print(node[0], depth + 1);
                    Out(" and conformance ");
                    Print(node[1], depth + 1);
                    return null;
                case K.ProtocolSelfConformanceWitnessTable: return Prefixed("protocol self-conformance witness table for ", node, depth);
                case K.ProtocolWitnessTableAccessor: return Prefixed("protocol witness table accessor for ", node, depth);
                case K.ProtocolWitnessTable: return Prefixed("protocol witness table for ", node, depth);
                case K.ProtocolWitnessTablePattern: return Prefixed("protocol witness table pattern for ", node, depth);
                case K.GenericProtocolWitnessTable: return Prefixed("generic protocol witness table for ", node, depth);
                case K.GenericProtocolWitnessTableInstantiationFunction: return Prefixed("instantiation function for generic protocol witness table for ", node, depth);
                case K.ResilientProtocolWitnessTable: return Prefixed("resilient protocol witness table for ", node, depth);
                case K.VTableThunk:
                    Out("vtable thunk for ");
                    Print(node[1], depth + 1);
                    Out(" dispatching to ");
                    Print(node[0], depth + 1);
                    return null;
                case K.ProtocolSelfConformanceWitness: return Prefixed("protocol self-conformance witness for ", node, depth);
                case K.ProtocolWitness:
                    Out("protocol witness for ");
                    Print(node[1], depth + 1);
                    Out(" in conformance ");
                    Print(node[0], depth + 1);
                    return null;
                case K.PartialApplyForwarder or K.PartialApplyObjCForwarder:
                    Out(opts.ShortenPartialApply ? "partial apply" : kind == K.PartialApplyForwarder ? "partial apply forwarder" : "partial apply ObjC forwarder");
                    if (node.HasChildren)
                    {
                        Out(" for ");
                        PrintChildren(node, depth);
                    }
                    return null;
                case K.KeyPathGetterThunkHelper or K.KeyPathSetterThunkHelper or K.KeyPathUnappliedMethodThunkHelper or K.KeyPathAppliedMethodThunkHelper:
                    Out(kind switch
                    {
                        K.KeyPathGetterThunkHelper => "key path getter for ",
                        K.KeyPathSetterThunkHelper => "key path setter for ",
                        K.KeyPathUnappliedMethodThunkHelper => "key path unapplied method ",
                        _ => "key path applied method ",
                    });
                    Print(node[0], depth + 1);
                    Out(" : ");
                    for (int i = 1; i < node.Count; i++)
                    {
                        if (node[i]!.Kind == K.IsSerialized) Out(", ");
                        Print(node[i], depth + 1);
                    }
                    return null;
                case K.KeyPathEqualsThunkHelper or K.KeyPathHashThunkHelper:
                {
                    Out("key path index ").Out(kind == K.KeyPathEqualsThunkHelper ? "equality" : "hash").Out(" operator for ");
                    int last = node.Count;
                    var lastChild = node[last - 1]!;
                    if (lastChild.Kind == K.IsSerialized)
                    {
                        last--;
                        lastChild = node[last - 1]!;
                    }
                    if (lastChild.Kind == K.DependentGenericSignature)
                    {
                        Print(lastChild, depth + 1);
                        last--;
                    }
                    Out("(");
                    for (int i = 0; i < last; i++)
                    {
                        if (i != 0) Out(", ");
                        Print(node[i], depth + 1);
                    }
                    Out(")");
                    return null;
                }
                case K.FieldOffset:
                    Print(node[0], depth + 1);
                    Out("field offset for ");
                    Print(node[1], depth + 1, false);
                    return null;
                case K.EnumCase:
                    Out("enum case for ");
                    Print(node[0], depth + 1, false);
                    return null;
                case K.ReabstractionThunk or K.ReabstractionThunkHelper:
                {
                    if (opts.ShortenThunk)
                    {
                        Out("thunk for ");
                        Print(node[node.Count - 1], depth + 1);
                        return null;
                    }
                    Out("reabstraction thunk ");
                    if (kind == K.ReabstractionThunkHelper) Out("helper ");
                    int idx = 0;
                    if (node.Count == 3)
                    {
                        idx = 1;
                        Print(node[0], depth + 1);
                        Out(" ");
                    }
                    Out("from ");
                    Print(node[idx + 1], depth + 1);
                    Out(" to ");
                    Print(node[idx], depth + 1);
                    return null;
                }
                case K.ReabstractionThunkHelperWithGlobalActor:
                    Print(node[0], depth + 1);
                    Out(" with global actor constraint ");
                    Print(node[1], depth + 1);
                    return null;
                case K.ReabstractionThunkHelperWithSelf:
                {
                    Out("reabstraction thunk ");
                    int idx = 0;
                    if (node.Count == 4)
                    {
                        idx = 1;
                        Print(node[0], depth + 1);
                        Out(" ");
                    }
                    Out("from ");
                    Print(node[idx + 2], depth + 1);
                    Out(" to ");
                    Print(node[idx + 1], depth + 1);
                    Out(" self ");
                    Print(node[idx], depth + 1);
                    return null;
                }
                case K.AutoDiffFunction or K.AutoDiffDerivativeVTableThunk:
                {
                    int prefixEnd = 0;
                    while (prefixEnd != node.Count && node[prefixEnd]!.Kind != K.AutoDiffFunctionKind) prefixEnd++;
                    var funcKind = node[prefixEnd];
                    var paramIndices = node[prefixEnd + 1];
                    var resultIndices = node[prefixEnd + 2];
                    if (kind == K.AutoDiffDerivativeVTableThunk) Out("vtable thunk for ");
                    Print(funcKind, depth + 1);
                    Out(" of ");
                    SwiftNode? genSig = null;
                    for (int i = 0; i < prefixEnd; i++)
                    {
                        if (i == prefixEnd - 1 && node[i]!.Kind == K.DependentGenericSignature)
                        {
                            genSig = node[i];
                            break;
                        }
                        Print(node[i], depth + 1);
                    }
                    if (opts.ShortenThunk) return null;
                    Out(" with respect to parameters ");
                    Print(paramIndices, depth + 1);
                    Out(" and results ");
                    Print(resultIndices, depth + 1);
                    if (genSig != null && opts.DisplayWhereClauses)
                    {
                        Out(" with ");
                        Print(genSig, depth + 1);
                    }
                    return null;
                }
                case K.AutoDiffSelfReorderingReabstractionThunk:
                {
                    Out("autodiff self-reordering reabstraction thunk ");
                    int at = 0;
                    var fromType = node[at++];
                    var toType = node[at++];
                    if (opts.ShortenThunk)
                    {
                        Out("for ");
                        Print(fromType, depth + 1);
                        return null;
                    }
                    var genSig = node[at]!.Kind == K.DependentGenericSignature ? node[at++] : null;
                    Out("for ");
                    Print(node[at++], depth + 1);
                    if (genSig != null)
                    {
                        Print(genSig, depth + 1);
                        Out(' ');
                    }
                    Out(" from ");
                    Print(fromType, depth + 1);
                    Out(" to ");
                    Print(toType, depth + 1);
                    return null;
                }
                case K.AutoDiffSubsetParametersThunk:
                {
                    if (node.Count < 5)
                    {
                        SetInvalid();
                        return null;
                    }
                    Out("autodiff subset parameters thunk for ");
                    int current = node.Count - 1;
                    var toParamIndices = node[current--];
                    var resultIndices = node[current--];
                    var paramIndices = node[current--];
                    var funcKind = node[current--];
                    Print(funcKind, depth + 1);
                    Out(" from ");
                    if (current == 0) Print(node.First, depth + 1);
                    else
                        for (int i = 0; i < current; i++) Print(node[i], depth + 1);
                    if (opts.ShortenThunk) return null;
                    Out(" with respect to parameters ");
                    Print(paramIndices, depth + 1);
                    Out(" and results ");
                    Print(resultIndices, depth + 1);
                    Out(" to parameters ");
                    Print(toParamIndices, depth + 1);
                    if (current > 0)
                    {
                        Out(" of type ");
                        Print(node[current], depth + 1);
                    }
                    return null;
                }
                case K.AutoDiffFunctionKind:
                    Out((char)node.Index switch
                    {
                        'f' => "forward-mode derivative",
                        'r' => "reverse-mode derivative",
                        'd' => "differential",
                        'p' => "pullback",
                        _ => "",
                    });
                    return null;
                case K.DifferentiabilityWitness:
                {
                    int kindIndex = node.Count - (node.Last!.Kind == K.DependentGenericSignature ? 4 : 3);
                    Out((char)node[kindIndex]!.Index switch
                    {
                        'f' => "forward-mode",
                        'r' => "reverse-mode",
                        'd' => "normal",
                        'l' => "linear",
                        _ => "",
                    });
                    Out(" differentiability witness for ");
                    int idx = 0;
                    for (; idx < node.Count && node[idx]!.Kind != K.Index; idx++) Print(node[idx], depth + 1);
                    idx++;
                    Out(" with respect to parameters ");
                    Print(node[idx++], depth + 1);
                    Out(" and results ");
                    Print(node[idx++], depth + 1);
                    if (idx < node.Count)
                    {
                        Out(" with ");
                        Print(node[idx], depth + 1);
                    }
                    return null;
                }
                case K.IndexSubset:
                {
                    Out('{');
                    bool any = false;
                    var t = node.Text!;
                    for (int i = 0; i < t.Length; i++)
                    {
                        if (t[i] != 'S') continue;
                        if (any) Out(", ");
                        Out((long)i);
                        any = true;
                    }
                    Out('}');
                    return null;
                }
                case K.MergedFunction:
                    if (!opts.ShortenThunk) Out("merged ");
                    return null;
                case K.TypeSymbolicReference:
                    Out("type symbolic reference 0x");
                    if (node.HasIndex) Hex(node.Index);
                    return null;
                case K.OpaqueTypeDescriptorSymbolicReference:
                    Out("opaque type symbolic reference 0x");
                    if (node.HasIndex) Hex(node.Index);
                    return null;
                case K.DistributedThunk:
                    if (!opts.ShortenThunk) Out("distributed thunk ");
                    return null;
                case K.DistributedAccessor:
                    if (!opts.ShortenThunk) Out("distributed accessor for ");
                    return null;
                case K.AccessibleFunctionRecord:
                    if (!opts.ShortenThunk) Out("accessible function runtime record for ");
                    return null;
                case K.DynamicallyReplaceableFunctionKey:
                    if (!opts.ShortenThunk) Out("dynamically replaceable key for ");
                    return null;
                case K.DynamicallyReplaceableFunctionImpl:
                    if (!opts.ShortenThunk) Out("dynamically replaceable thunk for ");
                    return null;
                case K.DynamicallyReplaceableFunctionVar:
                    if (!opts.ShortenThunk) Out("dynamically replaceable variable for ");
                    return null;
                case K.BackDeploymentThunk:
                    if (!opts.ShortenThunk) Out("back deployment thunk for ");
                    return null;
                case K.BackDeploymentFallback:
                    Out("back deployment fallback for ");
                    return null;
                case K.ProtocolSymbolicReference:
                    Out("protocol symbolic reference 0x");
                    Hex(node.Index);
                    return null;
                case K.GenericTypeMetadataPattern: return Prefixed("generic type metadata pattern for ", node, depth);
                case K.Metaclass: return Prefixed("metaclass for ", node, depth);
                case K.ProtocolSelfConformanceDescriptor: return Prefixed("protocol self-conformance descriptor for ", node, depth);
                case K.ProtocolConformanceDescriptor: return Prefixed("protocol conformance descriptor for ", node, depth);
                case K.ProtocolConformanceDescriptorRecord: return Prefixed("protocol conformance descriptor runtime record for ", node, depth);
                case K.ProtocolDescriptor: return Prefixed("protocol descriptor for ", node, depth);
                case K.ProtocolDescriptorRecord: return Prefixed("protocol descriptor runtime record for ", node, depth);
                case K.ProtocolRequirementsBaseDescriptor: return Prefixed("protocol requirements base descriptor for ", node, depth);
                case K.FullTypeMetadata: return Prefixed("full type metadata for ", node, depth);
                case K.TypeMetadata: return Prefixed("type metadata for ", node, depth);
                case K.TypeMetadataAccessFunction: return Prefixed("type metadata accessor for ", node, depth);
                case K.TypeMetadataInstantiationCache: return Prefixed("type metadata instantiation cache for ", node, depth);
                case K.TypeMetadataInstantiationFunction: return Prefixed("type metadata instantiation function for ", node, depth);
                case K.TypeMetadataSingletonInitializationCache: return Prefixed("type metadata singleton initialization cache for ", node, depth);
                case K.TypeMetadataCompletionFunction: return Prefixed("type metadata completion function for ", node, depth);
                case K.TypeMetadataDemanglingCache: return Prefixed("demangling cache variable for type metadata for ", node, depth);
                case K.TypeMetadataLazyCache: return Prefixed("lazy cache variable for type metadata for ", node, depth);
                case K.AssociatedConformanceDescriptor or K.DefaultAssociatedConformanceAccessor:
                    Out(kind == K.AssociatedConformanceDescriptor ? "associated conformance descriptor for " : "default associated conformance accessor for ");
                    Print(node[0], depth + 1);
                    Out(".");
                    Print(node[1], depth + 1);
                    Out(": ");
                    Print(node[2], depth + 1);
                    return null;
                case K.AssociatedTypeDescriptor: return Prefixed("associated type descriptor for ", node, depth);
                case K.AssociatedTypeMetadataAccessor:
                    Out("associated type metadata accessor for ");
                    Print(node[1], depth + 1);
                    Out(" in ");
                    Print(node[0], depth + 1);
                    return null;
                case K.BaseConformanceDescriptor:
                    Out("base conformance descriptor for ");
                    Print(node[0], depth + 1);
                    Out(": ");
                    Print(node[1], depth + 1);
                    return null;
                case K.DefaultAssociatedTypeMetadataAccessor: return Prefixed("default associated type metadata accessor for ", node, depth);
                case K.AssociatedTypeWitnessTableAccessor:
                    Out("associated type witness table accessor for ");
                    Print(node[1], depth + 1);
                    Out(" : ");
                    Print(node[2], depth + 1);
                    Out(" in ");
                    Print(node[0], depth + 1);
                    return null;
                case K.BaseWitnessTableAccessor:
                    Out("base witness table accessor for ");
                    Print(node[1], depth + 1);
                    Out(" in ");
                    Print(node[0], depth + 1);
                    return null;
                case K.ClassMetadataBaseOffset: return Prefixed("class metadata base offset for ", node, depth);
                case K.PropertyDescriptor: return Prefixed("property descriptor for ", node, depth);
                case K.NominalTypeDescriptor: return Prefixed("nominal type descriptor for ", node, depth);
                case K.NominalTypeDescriptorRecord: return Prefixed("nominal type descriptor runtime record for ", node, depth);
                case K.OpaqueTypeDescriptor: return Prefixed("opaque type descriptor for ", node, depth);
                case K.OpaqueTypeDescriptorRecord: return Prefixed("opaque type descriptor runtime record for ", node, depth);
                case K.OpaqueTypeDescriptorAccessor: return Prefixed("opaque type descriptor accessor for ", node, depth);
                case K.OpaqueTypeDescriptorAccessorImpl: return Prefixed("opaque type descriptor accessor impl for ", node, depth);
                case K.OpaqueTypeDescriptorAccessorKey: return Prefixed("opaque type descriptor accessor key for ", node, depth);
                case K.OpaqueTypeDescriptorAccessorVar: return Prefixed("opaque type descriptor accessor var for ", node, depth);
                case K.CoroutineContinuationPrototype: return Prefixed("coroutine continuation prototype for ", node, depth);
                case K.ValueWitness:
                {
                    ulong vw = node.First!.Index;
                    Out(vw < (ulong)ValueWitnessNames.Length ? ValueWitnessNames[vw] : "");
                    Out(opts.ShortenValueWitness ? " for " : " value witness for ");
                    Print(node[1], depth + 1);
                    return null;
                }
                case K.ValueWitnessTable: return Prefixed("value witness table for ", node, depth);
                case K.BoundGenericClass or K.BoundGenericStructure or K.BoundGenericEnum or K.BoundGenericProtocol or K.BoundGenericOtherNominalType
                    or K.BoundGenericTypeAlias:
                    PrintBoundGeneric(node, depth);
                    return null;
                case K.DynamicSelf or K.ConstrainedExistentialSelf:
                    Out("Self");
                    return null;
                case K.SILBoxType: return Prefixed("@box ", node, depth);
                case K.Metatype:
                {
                    int idx = 0;
                    if (node.Count == 2)
                    {
                        Print(node[idx], depth + 1);
                        Out(" ");
                        idx++;
                    }
                    var type = node[idx]!.First!;
                    PrintWithParens(type, depth);
                    Out(IsExistentialType(type) ? ".Protocol" : ".Type");
                    return null;
                }
                case K.ConstrainedExistential:
                    Out("any ");
                    Print(node[0], depth + 1);
                    Out("<");
                    Print(node[1], depth + 1);
                    Out(">");
                    return null;
                case K.ConstrainedExistentialRequirementList:
                    PrintChildren(node, depth, ", ");
                    return null;
                case K.ExistentialMetatype:
                {
                    int idx = 0;
                    if (node.Count == 2)
                    {
                        Print(node[idx], depth + 1);
                        Out(" ");
                        idx++;
                    }
                    Print(node[idx], depth + 1);
                    Out(".Type");
                    return null;
                }
                case K.AssociatedTypeRef:
                    Print(node[0], depth + 1);
                    Out('.').Out(node[1]!.Text);
                    return null;
                case K.ProtocolList:
                {
                    var list = node[0];
                    if (list == null) return null;
                    if (list.Count == 0) Out("Any");
                    else PrintChildren(list, depth, " & ");
                    return null;
                }
                case K.ProtocolListWithClass:
                {
                    if (node.Count < 2) return null;
                    Print(node[1], depth + 1);
                    Out(" & ");
                    if (node[0]!.Count < 1) return null;
                    PrintChildren(node[0]![0], depth, " & ");
                    return null;
                }
                case K.ProtocolListWithAnyObject:
                {
                    if (node.Count < 1) return null;
                    var protocols = node[0]!;
                    if (protocols.Count < 1) return null;
                    var list = protocols[0]!;
                    if (list.Count > 0)
                    {
                        PrintChildren(list, depth, " & ");
                        Out(" & ");
                    }
                    if (opts.QualifyEntities && opts.DisplayStdlibModule) Out("Swift.");
                    Out("AnyObject");
                    return null;
                }
                case K.AssociatedType: return null;
                case K.OwningAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "owningAddressor");
                case K.OwningMutableAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "owningMutableAddressor");
                case K.NativeOwningAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "nativeOwningAddressor");
                case K.NativeOwningMutableAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "nativeOwningMutableAddressor");
                case K.NativePinningAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "nativePinningAddressor");
                case K.NativePinningMutableAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "nativePinningMutableAddressor");
                case K.UnsafeAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "unsafeAddressor");
                case K.UnsafeMutableAddressor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "unsafeMutableAddressor");
                case K.GlobalGetter or K.Getter: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "getter");
                case K.Setter: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "setter");
                case K.MaterializeForSet: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "materializeForSet");
                case K.WillSet: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "willset");
                case K.DidSet: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "didset");
                case K.ReadAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "read");
                case K.YieldingBorrowAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "yielding_borrow");
                case K.ModifyAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "modify");
                case K.YieldingMutateAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "yielding_mutate");
                case K.InitAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "init");
                case K.BorrowAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "borrow");
                case K.MutateAccessor: return PrintAbstractStorage(node.First!, depth, asPrefixContext, "mutate");
                case K.Allocator:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.FunctionStyle, false, node[0]!.Kind == K.Class ? "__allocating_init" : "init");
                case K.Constructor: return PrintEntity(node, depth, asPrefixContext, TypePrinting.FunctionStyle, node.Count > 2, "init");
                case K.Destructor: return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "deinit");
                case K.Deallocator:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, node[0]!.Kind == K.Class ? "__deallocating_deinit" : "deinit");
                case K.IsolatedDeallocator:
                    return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false,
                        node[0]!.Kind == K.Class ? "__isolated_deallocating_deinit" : "deinit");
                case K.IVarInitializer: return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "__ivar_initializer");
                case K.IVarDestroyer: return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, false, "__ivar_destroyer");
                case K.ProtocolConformance:
                {
                    var c0 = node[0];
                    var c1 = node[1];
                    var c2 = node[2];
                    if (node.Count == 4)
                    {
                        Out("property behavior storage of ");
                        Print(c2, depth + 1);
                        Out(" in ");
                        Print(c0, depth + 1);
                        Out(" : ");
                        Print(c1, depth + 1);
                    }
                    else
                    {
                        Print(c0, depth + 1);
                        if (opts.DisplayProtocolConformances)
                        {
                            Out(" : ");
                            Print(c1, depth + 1);
                            Out(" in ");
                            Print(c2, depth + 1);
                        }
                    }
                    return null;
                }
                case K.TypeList:
                    PrintChildren(node, depth);
                    return null;
                case K.LabelList: return null;
                case K.ImplDifferentiabilityKind:
                    Out("@differentiable");
                    Out((char)node.Index switch { 'l' => "(_linear)", 'f' => "(_forward)", 'r' => "(reverse)", _ => "" });
                    return null;
                case K.ImplEscaping:
                    Out("@escaping");
                    return null;
                case K.ImplNonisolatedNonsendingIsolation:
                    Out("@caller_isolated");
                    return null;
                case K.ImplErasedIsolation:
                    Out("@isolated(any)");
                    return null;
                case K.ImplCalledOnceFunction:
                    Out("@called(exactlyOnce)");
                    return null;
                case K.ImplCalledAtMostOnceFunction:
                    Out("@called(atMostOnce)");
                    return null;
                case K.ImplCoroutineKind:
                    if (node.Text!.Length > 0) Out('@').Out(node.Text);
                    return null;
                case K.ImplSendingResult:
                    Out("sending");
                    return null;
                case K.ImplParameterResultDifferentiability or K.ImplParameterSending or K.ImplParameterIsolated or K.ImplParameterImplicitLeading:
                    if (node.Text!.Length > 0) Out(node.Text).Out(' ');
                    return null;
                case K.ImplFunctionConvention:
                    Out("@convention(");
                    switch (node.Count)
                    {
                        case 1: Out(node[0]!.Text); break;
                        case 2:
                            Out(node[0]!.Text).Out(", mangledCType: \"");
                            Print(node[1], depth + 1);
                            Out('"');
                            break;
                    }
                    Out(')');
                    return null;
                case K.ImplFunctionConventionName: return null;
                case K.ImplErrorResult:
                    Out("@error ");
                    PrintChildren(node, depth, " ");
                    return null;
                case K.ImplYield:
                    Out("@yields ");
                    PrintChildren(node, depth, " ");
                    return null;
                case K.ImplParameter or K.ImplResult:
                    Print(node[0], depth + 1);
                    Out(" ");
                    if (node.Count == 3) Print(node[1], depth + 1);
                    if (node.Count == 4)
                    {
                        Print(node[1], depth + 1);
                        Print(node[2], depth + 1);
                    }
                    Print(node.Last, depth + 1);
                    return null;
                case K.ImplFunctionType:
                    PrintImplFunctionType(node, depth);
                    return null;
                case K.ImplInvocationSubstitutions:
                    Out("for <");
                    PrintChildren(node[0], depth, ", ");
                    Out('>');
                    return null;
                case K.ImplPatternSubstitutions:
                    Out("@substituted ");
                    Print(node[0], depth + 1);
                    Out(" for <");
                    PrintChildren(node[1], depth, ", ");
                    Out('>');
                    return null;
                case K.ErrorType:
                    Out("<ERROR TYPE>");
                    return null;
                case K.DependentPseudogenericSignature or K.DependentGenericSignature:
                    PrintGenericSignature(node, depth);
                    return null;
                case K.DependentGenericParamCount or K.DependentGenericParamPackMarker or K.DependentGenericParamValueMarker or K.PackElementLevel:
                    SetInvalid();
                    return null;
                case K.DependentGenericConformanceRequirement:
                    Print(node[0], depth + 1);
                    Out(": ");
                    Print(node[1], depth + 1);
                    return null;
                case K.DependentGenericInverseConformanceRequirement:
                    Print(node[0], depth + 1);
                    Out(": ~");
                    Out(node[1]!.Index switch
                    {
                        0 => "Swift." + InvertibleCopyable,
                        1 => "Swift." + InvertibleEscapable,
                        2 => "Swift." + InvertibleDeinitable,
                        var bit => $"Swift.<bit {bit}>",
                    });
                    return null;
                case K.DependentGenericLayoutRequirement:
                {
                    Print(node[0], depth + 1);
                    Out(": ");
                    var layout = node[1]!.Text!;
                    Out(layout switch
                    {
                        "U" => "_UnknownLayout",
                        "R" => "_RefCountedObject",
                        "N" => "_NativeRefCountedObject",
                        "C" => "AnyObject",
                        "D" => "_NativeClass",
                        "T" or "E" or "e" => "_Trivial",
                        "M" or "m" => "_TrivialAtMost",
                        _ => "",
                    });
                    if (node.Count > 2)
                    {
                        Out("(");
                        Print(node[2], depth + 1);
                        if (node.Count > 3)
                        {
                            Out(", ");
                            Print(node[3], depth + 1);
                        }
                        Out(")");
                    }
                    return null;
                }
                case K.DependentGenericSameTypeRequirement:
                    Print(node[0], depth + 1);
                    Out(" == ");
                    Print(node[1], depth + 1);
                    return null;
                case K.DependentGenericSameShapeRequirement:
                    Print(node[0], depth + 1);
                    Out(".shape == ");
                    Print(node[1], depth + 1);
                    Out(".shape");
                    return null;
                case K.DependentGenericParamType:
                    Out(GenericParameterName(node[0]!.Index, node[1]!.Index));
                    return null;
                case K.DependentGenericType:
                {
                    var depTy = node[1]!;
                    Print(node[0], depth + 1);
                    if (NeedSpaceBeforeType(depTy)) Out(' ');
                    Print(depTy, depth + 1);
                    return null;
                }
                case K.DependentMemberType:
                    Print(node[0], depth + 1);
                    Out('.');
                    Print(node[1], depth + 1);
                    return null;
                case K.DependentAssociatedTypeRef:
                    if (node.Count > 1)
                    {
                        Print(node[1], depth + 1);
                        Out('.');
                    }
                    Print(node[0], depth + 1);
                    return null;
                case K.ReflectionMetadataBuiltinDescriptor: return Prefixed("reflection metadata builtin descriptor ", node, depth);
                case K.ReflectionMetadataFieldDescriptor: return Prefixed("reflection metadata field descriptor ", node, depth);
                case K.ReflectionMetadataAssocTypeDescriptor: return Prefixed("reflection metadata associated type descriptor ", node, depth);
                case K.ReflectionMetadataSuperclassDescriptor: return Prefixed("reflection metadata superclass descriptor ", node, depth);
                case K.ConcurrentFunctionType:
                    Out("@Sendable ");
                    return null;
                case K.DifferentiableFunctionType:
                    Out("@differentiable");
                    Out((char)node.Index switch { 'f' => "(_forward)", 'r' => "(reverse)", 'l' => "(_linear)", _ => "" });
                    Out(' ');
                    return null;
                case K.GlobalActorFunctionType:
                    if (node.Count > 0)
                    {
                        Out('@');
                        Print(node[0], depth + 1);
                        Out(' ');
                    }
                    return null;
                case K.IsolatedAnyFunctionType:
                    Out("@isolated(any) ");
                    return null;
                case K.NonIsolatedCallerFunctionType:
                    Out("nonisolated(nonsending) ");
                    return null;
                case K.SendingResultFunctionType:
                    Out("sending ");
                    return null;
                case K.AsyncAnnotation:
                    Out(" async");
                    return null;
                case K.ThrowsAnnotation:
                    Out(" throws");
                    return null;
                case K.TypedThrowsAnnotation:
                    Out(" throws(");
                    if (node.Count == 1) Print(node[0], depth + 1);
                    Out(")");
                    return null;
                case K.EmptyList:
                    Out(" empty-list ");
                    return null;
                case K.FirstElementMarker:
                    Out(" first-element-marker ");
                    return null;
                case K.VariadicMarker:
                    Out(" variadic-marker ");
                    return null;
                case K.SILBoxTypeWithLayout:
                {
                    var layout = node[0];
                    SwiftNode? genericArgs = null;
                    if (node.Count == 3)
                    {
                        genericArgs = node[2];
                        Print(node[1], depth + 1);
                        Out(' ');
                    }
                    Print(layout, depth + 1);
                    if (genericArgs != null)
                    {
                        Out(" <");
                        for (int i = 0; i < genericArgs.Count; i++)
                        {
                            if (i > 0) Out(", ");
                            Print(genericArgs[i], depth + 1);
                        }
                        Out('>');
                    }
                    return null;
                }
                case K.SILBoxLayout:
                    Out('{');
                    for (int i = 0; i < node.Count; i++)
                    {
                        if (i > 0) Out(',');
                        Out(' ');
                        Print(node[i], depth + 1);
                    }
                    Out(" }");
                    return null;
                case K.SILBoxImmutableField or K.SILBoxMutableField:
                    Out(kind == K.SILBoxImmutableField ? "let " : "var ");
                    Print(node[0], depth + 1);
                    return null;
                case K.AssocTypePath:
                    PrintChildren(node, depth, ".");
                    return null;
                case K.ModuleDescriptor: return Prefixed("module descriptor ", node, depth);
                case K.AnonymousDescriptor: return Prefixed("anonymous descriptor ", node, depth);
                case K.ExtensionDescriptor: return Prefixed("extension descriptor ", node, depth);
                case K.AssociatedTypeGenericParamRef:
                    Out("generic parameter reference for associated type ");
                    PrintChildren(node, depth);
                    return null;
                case K.AnyProtocolConformanceList:
                    if (node.Count > 0)
                    {
                        Out("(");
                        for (int i = 0; i < node.Count; i++)
                        {
                            if (i > 0) Out(", ");
                            Print(node[i], depth + 1);
                        }
                        Out(")");
                    }
                    return null;
                case K.ConcreteProtocolConformance:
                    Out("concrete protocol conformance ");
                    if (node.HasIndex) Out("#").Out(node.Index).Out(" ");
                    Print(node[0], depth + 1);
                    Out(" to ");
                    Print(node[1], depth + 1);
                    if (node.Count > 2 && node[2]!.Count > 0)
                    {
                        Out(" with conditional requirements: ");
                        Print(node[2], depth + 1);
                    }
                    return null;
                case K.PackProtocolConformance:
                    Out("pack protocol conformance ");
                    PrintChildren(node, depth);
                    return null;
                case K.DependentAssociatedConformance:
                    Out("dependent associated conformance ");
                    PrintChildren(node, depth);
                    return null;
                case K.DependentProtocolConformanceAssociated or K.DependentProtocolConformanceInherited or K.DependentProtocolConformanceRoot:
                    Out(kind switch
                    {
                        K.DependentProtocolConformanceAssociated => "dependent associated protocol conformance ",
                        K.DependentProtocolConformanceInherited => "dependent inherited protocol conformance ",
                        _ => "dependent root protocol conformance ",
                    });
                    PrintOptionalIndex(node[2]!);
                    Print(node[0], depth + 1);
                    Out(" to ");
                    Print(node[1], depth + 1);
                    return null;
                case K.DependentProtocolConformanceOpaque:
                    Out("opaque result conformance ");
                    Print(node[0], depth + 1);
                    Out(" of ");
                    Print(node[1], depth + 1);
                    return null;
                case K.ProtocolConformanceRefInTypeModule:
                    Out("protocol conformance ref (type's module) ");
                    PrintChildren(node, depth);
                    return null;
                case K.ProtocolConformanceRefInProtocolModule:
                    Out("protocol conformance ref (protocol's module) ");
                    PrintChildren(node, depth);
                    return null;
                case K.ProtocolConformanceRefInOtherModule:
                    Out("protocol conformance ref (retroactive) ");
                    PrintChildren(node, depth);
                    return null;
                case K.SugaredOptional:
                    PrintWithParens(node[0]!, depth);
                    Out("?");
                    return null;
                case K.SugaredArray:
                    Out("[");
                    Print(node[0], depth + 1);
                    Out("]");
                    return null;
                case K.SugaredInlineArray:
                    Out("[");
                    Print(node[0], depth + 1);
                    Out(" of ");
                    Print(node[1], depth + 1);
                    Out("]");
                    return null;
                case K.SugaredDictionary:
                    Out("[");
                    Print(node[0], depth + 1);
                    Out(" : ");
                    Print(node[1], depth + 1);
                    Out("]");
                    return null;
                case K.SugaredParen:
                    Out("(");
                    Print(node[0], depth + 1);
                    Out(")");
                    return null;
                case K.OpaqueReturnType:
                    Out("some");
                    return null;
                case K.OpaqueReturnTypeOf:
                    Out("<<opaque return type of ");
                    PrintChildren(node, depth);
                    Out(">>");
                    return null;
                case K.OpaqueType:
                    Print(node[0], depth + 1);
                    Out('.');
                    Print(node[1], depth + 1);
                    return null;
                case K.AccessorFunctionReference:
                    Out("accessor function at ").Out(node.Index);
                    return null;
                case K.CanonicalSpecializedGenericMetaclass: return Prefixed("specialized generic metaclass for ", node, depth);
                case K.CanonicalSpecializedGenericTypeMetadataAccessFunction:
                    return Prefixed("canonical specialized generic type metadata accessor for ", node, depth);
                case K.MetadataInstantiationCache: return Prefixed("metadata instantiation cache for ", node, depth);
                case K.NoncanonicalSpecializedGenericTypeMetadata: return Prefixed("noncanonical specialized generic type metadata for ", node, depth);
                case K.NoncanonicalSpecializedGenericTypeMetadataCache:
                    return Prefixed("cache variable for noncanonical specialized generic type metadata for ", node, depth);
                case K.GlobalVariableOnceToken or K.GlobalVariableOnceFunction:
                    Out(kind == K.GlobalVariableOnceToken ? "one-time initialization token for " : "one-time initialization function for ");
                    PrintContext(node[0]!);
                    Print(node[1], depth + 1);
                    return null;
                case K.GlobalVariableOnceDeclList:
                    if (node.Count == 1) Print(node[0], depth + 1);
                    else
                    {
                        Out('(');
                        for (int i = 0; i < node.Count; i++)
                        {
                            if (i != 0) Out(", ");
                            Print(node[i], depth + 1);
                        }
                        Out(')');
                    }
                    return null;
                case K.CheckedObjCAsyncCompletionHandlerImpl or K.ObjCAsyncCompletionHandlerImpl:
                    if (kind == K.CheckedObjCAsyncCompletionHandlerImpl) Out("checked ");
                    Out("@objc completion handler block implementation for ");
                    if (node.Count >= 4) Print(node[3], depth + 1);
                    Print(node[0], depth + 1);
                    Out(" with result type ");
                    Print(node[1], depth + 1);
                    Out(node[2]!.Index switch { 0 => "", 1 => " nonzero on error", 2 => " zero on error", _ => " <invalid error flag>" });
                    return null;
                case K.CanonicalPrespecializedGenericTypeCachingOnceToken:
                    return Prefixed("flag for loading of canonical specialized generic type metadata for ", node, depth);
                case K.AsyncFunctionPointer:
                    Out("async function pointer to ");
                    return null;
                case K.AsyncMainEntryPoint:
                    Out("async main entry point");
                    return null;
                case K.AsyncAwaitResumePartialFunction or K.AsyncSuspendResumePartialFunction:
                    if (opts.ShowAsyncResumePartial)
                    {
                        Out("(");
                        Print(node[0], depth + 1);
                        Out(")");
                        Out(kind == K.AsyncAwaitResumePartialFunction ? " await resume partial function for " : " suspend resume partial function for ");
                    }
                    return null;
                case K.Uniquable: return Prefixed("uniquable ", node, depth);
                case K.ExtendedExistentialTypeShape:
                {
                    var saved = opts;
                    opts = opts with { DisplayWhereClauses = true };
                    SwiftNode? genSig = null, type;
                    if (node.Count == 2)
                    {
                        genSig = node[1];
                        type = node[2];
                    }
                    else type = node[1];
                    Out("existential shape for ");
                    if (genSig != null)
                    {
                        Print(genSig, depth + 1);
                        Out(" ");
                    }
                    Out("any ");
                    Print(type, depth + 1);
                    opts = saved;
                    return null;
                }
                case K.UniqueExtendedExistentialTypeShapeSymbolicReference:
                    Out("unique existential shape symbolic reference 0x");
                    Hex(node.Index);
                    return null;
                case K.NonUniqueExtendedExistentialTypeShapeSymbolicReference:
                    Out("non-unique existential shape symbolic reference 0x");
                    Hex(node.Index);
                    return null;
                case K.ObjectiveCProtocolSymbolicReference:
                    Out("objective-c protocol symbolic reference 0x");
                    Hex(node.Index);
                    return null;
                case K.SymbolicExtendedExistentialType:
                {
                    var shape = node[0]!;
                    bool unique = shape.Kind == K.UniqueExtendedExistentialTypeShapeSymbolicReference;
                    Out("symbolic existential type (").Out(unique ? "" : "non-").Out("unique) 0x");
                    Hex(shape.Index);
                    Out(" <");
                    Print(node[1], depth + 1);
                    if (node.Count > 2)
                    {
                        Out(", ");
                        Print(node[2], depth + 1);
                    }
                    Out(">");
                    return null;
                }
                case K.HasSymbolQuery:
                    Out("#_hasSymbol query for ");
                    return null;
                case K.OpaqueReturnTypeIndex or K.OpaqueReturnTypeParent: return null;
                case K.NegativeInteger:
                    Out(unchecked((long)node.Index));
                    return null;
                case K.CoroFunctionPointer:
                    Out("coro function pointer to ");
                    return null;
                case K.DefaultOverride:
                    Out("default override of ");
                    return null;
                default:
                    SetInvalid();
                    return null;
            }
        }

        private SwiftNode? Prefixed(string text, SwiftNode node, int depth)
        {
            Out(text);
            Print(node[0], depth + 1);
            return null;
        }

        private SwiftNode? AttachedMacro(SwiftNode node, int depth, bool asPrefixContext, string role)
        {
            var name = Print(node[2]!);
            return PrintEntity(node, depth, asPrefixContext, TypePrinting.NoType, true, role + " macro @" + name + " expansion #", (int)node[3]!.Index + 1);
        }

        /// <summary>A subtree printed on its own, with these options.</summary>
        private string Print(SwiftNode node)
        {
            var p = new Printer(opts);
            p.Print(node, 0);
            return p.Valid ? p.Text : "";
        }

        private void PrintParamKind(ulong raw)
        {
            bool printed = false;
            void Option(FuncSigParamKind flag, string text)
            {
                if ((raw & (ulong)flag) == 0) return;
                if (printed) Out(" and ");
                printed = true;
                Out(text);
            }
            Option(FuncSigParamKind.ExistentialToGeneric, "Existential To Protocol Constrained Generic");
            Option(FuncSigParamKind.Dead, "Dead");
            Option(FuncSigParamKind.OwnedToGuaranteed, "Owned To Guaranteed");
            Option(FuncSigParamKind.GuaranteedToOwned, "Guaranteed To Owned");
            if ((raw & (ulong)FuncSigParamKind.SROA) != 0)
            {
                if (printed) Out(" and ");
                Out("Exploded");
                return;
            }
            if (printed) return;
            Out((FuncSigParamKind)raw switch
            {
                FuncSigParamKind.BoxToValue => "Value Promoted from Box",
                FuncSigParamKind.BoxToStack => "Stack Promoted from Box",
                FuncSigParamKind.InOutToOut => "InOut Converted to Out",
                FuncSigParamKind.ConstantPropFunction => "Constant Propagated Function",
                FuncSigParamKind.ConstantPropGlobal => "Constant Propagated Global",
                FuncSigParamKind.ConstantPropInteger => "Constant Propagated Integer",
                FuncSigParamKind.ConstantPropFloat => "Constant Propagated Float",
                FuncSigParamKind.ConstantPropString => "Constant Propagated String",
                FuncSigParamKind.ConstantPropKeyPath => "Constant Propagated KeyPath",
                FuncSigParamKind.ConstantPropStruct => "Constant Propagated Struct",
                FuncSigParamKind.ClosureProp => "Closure Propagated",
                FuncSigParamKind.EscapingClosureProp => "Escaping Closure Propagated",
                FuncSigParamKind.ClosurePropPreviousArg => "Same As Argument",
                _ => "",
            });
        }

        private static string Quoted(string value)
        {
            var q = new StringBuilder("\"");
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': q.Append("\\\\"); break;
                    case '\t': q.Append("\\t"); break;
                    case '\n': q.Append("\\n"); break;
                    case '\r': q.Append("\\r"); break;
                    case '"': q.Append("\\\""); break;
                    case '\0': q.Append("\\0"); break;
                    default:
                        if (c < 0x20 || c >= 0x7F)
                            foreach (byte b in Encoding.UTF8.GetBytes(c.ToString())) q.Append("\\x").Append(b.ToString("X2", CultureInfo.InvariantCulture));
                        else q.Append(c);
                        break;
                }
            }
            return q.Append('"').ToString();
        }

        private SwiftNode? PrintAbstractStorage(SwiftNode node, int depth, bool asPrefixContext, string extraName) => node.Kind switch
        {
            K.Variable => PrintEntity(node, depth, asPrefixContext, TypePrinting.WithColon, true, extraName),
            K.Subscript => PrintEntity(node, depth, asPrefixContext, TypePrinting.WithColon, false, extraName, -1, "subscript"),
            _ => Invalid(),
        };

        private SwiftNode? Invalid()
        {
            SetInvalid();
            return null;
        }

        private SwiftNode? PrintEntity(SwiftNode entity, int depth, bool asPrefixContext, TypePrinting typePr, bool hasName, string extraName = "",
            int extraIndex = -1, string overwriteName = "")
        {
            SwiftNode? genericFunctionTypeList = null;
            if (entity.Kind == K.BoundGenericFunction)
            {
                genericFunctionTypeList = entity[1];
                entity = entity.First!;
            }
            bool multiWordName = extraName.Contains(' ', StringComparison.Ordinal);
            bool localName = hasName && entity[1]!.Kind == K.LocalDeclName;
            if (localName && opts.DisplayLocalNameContexts) multiWordName = true;
            if (asPrefixContext && (typePr != TypePrinting.NoType || multiWordName)) return entity;

            SwiftNode? postfixContext = null;
            var context = entity[0]!;
            if (PrintContext(context))
            {
                if (multiWordName) postfixContext = context;
                else
                {
                    int before = sb.Length;
                    postfixContext = Print(context, depth + 1, true);
                    if (sb.Length != before) Out('.');
                }
            }
            PrintFunctionName(hasName, overwriteName, ref extraName, multiWordName, ref extraIndex, entity, depth);
            if (typePr != TypePrinting.NoType)
            {
                var typeNode = ChildIf(entity, K.Type);
                if (typeNode == null)
                {
                    SetInvalid();
                    return null;
                }
                var type = typeNode[0]!;
                if (typePr == TypePrinting.FunctionStyle)
                {
                    var t = type;
                    while (t.Kind == K.DependentGenericType) t = t[1]![0]!;
                    if (t.Kind is not (K.FunctionType or K.NoEscapeFunctionType or K.UncurriedFunctionType or K.CFunctionPointer or K.ThinFunctionType
                        or K.CalledOnceFunctionType or K.CalledAtMostOnceFunctionType))
                        typePr = TypePrinting.WithColon;
                }
                if (typePr == TypePrinting.WithColon)
                {
                    if (opts.DisplayEntityTypes)
                    {
                        Out(" : ");
                        PrintEntityType(entity, type, genericFunctionTypeList, depth);
                    }
                }
                else if (entity.Kind is not (K.ExplicitClosure or K.ImplicitClosure) || opts.ShowClosureSignature)
                {
                    if (multiWordName || NeedSpaceBeforeType(type)) Out(' ');
                    PrintEntityType(entity, type, genericFunctionTypeList, depth);
                }
            }
            if (!asPrefixContext && postfixContext != null && (!localName || opts.DisplayLocalNameContexts))
            {
                Out(entity.Kind is K.DefaultArgumentInitializer or K.Initializer or K.PropertyWrapperBackingInitializer or K.PropertyWrappedFieldInitAccessor
                    or K.PropertyWrapperInitFromProjectedValue ? " of " : " in ");
                Print(postfixContext, depth + 1);
                postfixContext = null;
            }
            return postfixContext;
        }

        private void PrintFunctionName(bool hasName, string overwriteName, ref string extraName, bool multiWordName, ref int extraIndex, SwiftNode entity, int depth)
        {
            if (hasName || overwriteName.Length > 0)
            {
                if (extraName.Length > 0 && multiWordName)
                {
                    Out(extraName);
                    if (extraIndex >= 0) Out((long)extraIndex);
                    Out(" of ");
                    extraName = "";
                    extraIndex = -1;
                }
                int before = sb.Length;
                if (overwriteName.Length > 0) Out(overwriteName);
                else
                {
                    var name = entity[1]!;
                    if (name.Kind != K.PrivateDeclName) Print(name, depth + 1);
                    if (ChildIf(entity, K.PrivateDeclName) is { } privateName) Print(privateName, depth + 1);
                }
                if (sb.Length != before && extraName.Length > 0) Out('.');
            }
            if (extraName.Length > 0)
            {
                Out(extraName);
                if (extraIndex >= 0) Out((long)extraIndex);
            }
        }

        private void PrintEntityType(SwiftNode entity, SwiftNode type, SwiftNode? genericFunctionTypeList, int depth)
        {
            var labelList = ChildIf(entity, K.LabelList);
            if (labelList != null || genericFunctionTypeList != null)
            {
                if (genericFunctionTypeList != null)
                {
                    Out("<");
                    PrintChildren(genericFunctionTypeList, depth, ", ");
                    Out(">");
                }
                if (type.Kind == K.DependentGenericType)
                {
                    if (genericFunctionTypeList == null) Print(type[0], depth + 1);
                    var dependent = type[1]!;
                    if (NeedSpaceBeforeType(dependent)) Out(' ');
                    type = dependent.First!;
                }
                PrintFunctionType(labelList, type, depth);
            }
            else Print(type, depth + 1);
        }
    }
}
