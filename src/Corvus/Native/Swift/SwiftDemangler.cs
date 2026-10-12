using System.Runtime.CompilerServices;
using System.Text;

namespace Corvus.Native.Swift;

/// <summary>
/// Demangles Swift symbol and type names into the text swift-demangle prints (sugared types): the Swift 4+ manglings
/// ("$s", "_$s", "$S", "_T0", "$e", "@__swiftmacro_", "async_Main"), the Swift 1-3 mangling ("_T", including the "_Tt"
/// ObjC runtime names of Swift classes) and metadata type references with symbolic references resolved by the caller.
/// Names it cannot parse yield null; no input throws.
/// </summary>
public static partial class SwiftDemangler
{
    /// <summary>Longest name accepted; longer input is returned as not demangled.</summary>
    public const int MaxLength = 1 << 16;
    /// <summary>Most nodes one demangling builds; pathological substitution chains stop here.</summary>
    internal const int MaxNodes = 1 << 16;
    /// <summary>Longest printed text; shared subtrees cannot expand past it.</summary>
    internal const int MaxOutput = 1 << 16;

    internal sealed class TooComplex : Exception;

    private static readonly string[] Prefixes = ["_T0", "$S", "_$S", "$s", "_$s", "$e", "_$e", "@__swiftmacro_"];
    private const string AsyncMain = "async_Main";

    /// <summary>
    /// The demangled form of <paramref name="name"/>, or null when it is not a Swift mangled name or does not parse.
    /// A Mach-O symbol's extra leading underscore is accepted ("__T0...", "_$s...").
    /// </summary>
    public static string? Demangle(string? name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxLength) return null;
        if (name.StartsWith("__", StringComparison.Ordinal)) name = name[1..];
        if (!IsMangled(name)) return null;
        try
        {
            var root = DemangleSymbolAsNode(name, null);
            return root == null ? null : Print(root, PrintOptions.Default);
        }
        catch (Exception e) when (e is TooComplex or InsufficientExecutionStackException or NullReferenceException or ArgumentOutOfRangeException
                                       or IndexOutOfRangeException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Whether <paramref name="name"/> starts with a Swift mangling prefix (old "_T" included).</summary>
    public static bool IsMangled(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name.StartsWith("__", StringComparison.Ordinal)) name = name[1..];
        return name.StartsWith("_T", StringComparison.Ordinal) || PrefixLength(name) > 0 || AsyncMainLength(name) > 0;
    }

    /// <summary>
    /// A metadata mangled type name (field types, superclasses, generic arguments) as text. <paramref name="text"/> holds
    /// one char per byte; <paramref name="resolver"/> turns symbolic references into nodes (null refuses them).
    /// </summary>
    internal static string? DemangleType(string text, SymbolicResolver? resolver)
    {
        if (text.Length == 0 || text.Length > MaxLength) return null;
        try
        {
            var node = new Parser(text, resolver).DemangleType();
            return node == null ? null : Print(node, PrintOptions.Default);
        }
        catch (Exception e) when (e is TooComplex or InsufficientExecutionStackException or NullReferenceException or ArgumentOutOfRangeException
                                       or IndexOutOfRangeException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The node tree of a symbol (null when it does not parse); throws <see cref="TooComplex"/> on runaway input.</summary>
    internal static SwiftNode? DemangleSymbolAsNode(string name, SymbolicResolver? resolver)
    {
        if (PrefixLength(name) > 0 || AsyncMainLength(name) > 0) return new Parser(name, resolver).DemangleSymbol();
        return new OldParser(name).DemangleTopLevel();
    }

    /// <summary>The node tree of a metadata type name; throws <see cref="TooComplex"/> on runaway input.</summary>
    internal static SwiftNode? DemangleTypeAsNode(string text, SymbolicResolver? resolver) => new Parser(text, resolver).DemangleType();

    internal static int PrefixLength(string name)
    {
        foreach (var p in Prefixes)
            if (name.StartsWith(p, StringComparison.Ordinal)) return p.Length;
        return 0;
    }

    internal static int AsyncMainLength(string name)
    {
        if (name.StartsWith(AsyncMain, StringComparison.Ordinal)) return AsyncMain.Length;
        return name.Length > 1 && name[0] == '_' && name.AsSpan(1).StartsWith(AsyncMain, StringComparison.Ordinal) ? AsyncMain.Length + 1 : 0;
    }

    /// <summary>"A", "B", ..., "Z", "AB" ... with the depth appended when nonzero ("A1").</summary>
    internal static string GenericParameterName(ulong depth, ulong index)
    {
        var sb = new StringBuilder();
        do
        {
            sb.Append((char)('A' + (int)(index % 26)));
            index /= 26;
        } while (index != 0);
        if (depth != 0) sb.Append(depth);
        return sb.ToString();
    }

    internal static void CheckStack() => RuntimeHelpers.EnsureSufficientExecutionStack();
}

/// <summary>Kinds of symbolic reference in metadata mangled names.</summary>
internal enum SymbolicReferenceKind { Context, AccessorFunctionReference, UniqueExtendedExistentialTypeShape, NonUniqueExtendedExistentialTypeShape, ObjectiveCProtocol }

/// <summary>
/// Resolves a symbolic reference: <paramref name="value"/> is the 32-bit relative offset stored at char
/// <paramref name="offset"/> of the mangled text; null refuses it.
/// </summary>
internal delegate SwiftNode? SymbolicResolver(SymbolicReferenceKind kind, bool direct, int value, int offset);

/// <summary>A node of a demangled Swift name: a kind with text, an index or children.</summary>
internal sealed class SwiftNode(SwiftNodeKind kind)
{
    private List<SwiftNode>? children;

    public SwiftNodeKind Kind { get; } = kind;
    public string? Text { get; init; }
    public ulong Index { get; init; }
    public bool HasIndex { get; init; }
    public bool HasText => Text != null;
    public int Count => children?.Count ?? 0;
    public bool HasChildren => Count > 0;
    public IReadOnlyList<SwiftNode> Children => (IReadOnlyList<SwiftNode>?)children ?? [];

    /// <summary>The child at <paramref name="i"/>, or null past the end.</summary>
    public SwiftNode? this[int i] => children != null && i >= 0 && i < children.Count ? children[i] : null;
    public SwiftNode? First => this[0];
    public SwiftNode? Last => Count > 0 ? children![^1] : null;

    public void Add(SwiftNode child) => (children ??= []).Add(child);
    public void RemoveAt(int i) => children!.RemoveAt(i);
    public void Replace(int i, SwiftNode child) => children![i] = child;

    public void Reverse(int start = 0)
    {
        if (children != null && start < children.Count) children.Reverse(start, children.Count - start);
    }

    public override string ToString() => Kind + (Text != null ? $" \"{Text}\"" : HasIndex ? $" {Index}" : "") + (Count > 0 ? $" [{Count}]" : "");
}

internal enum SwiftNodeKind
{
    Allocator, AnonymousContext, AnyProtocolConformanceList, ArgumentTuple, AssociatedType, AssociatedTypeRef, AssociatedTypeMetadataAccessor, DefaultAssociatedTypeMetadataAccessor,
    AccessorAttachedMacroExpansion, AssociatedTypeWitnessTableAccessor, BaseWitnessTableAccessor, AutoClosureType, BodyAttachedMacroExpansion, BoundGenericClass, BoundGenericEnum, BoundGenericStructure,
    BoundGenericProtocol, BoundGenericOtherNominalType, BoundGenericTypeAlias, BoundGenericFunction, BuiltinTypeName, BuiltinTupleType, BuiltinFixedArray, BuiltinBorrow,
    CFunctionPointer, ClangType, Class, ClassMetadataBaseOffset, ConcreteProtocolConformance, PackProtocolConformance, ConformanceAttachedMacroExpansion, Constructor,
    CoroutineContinuationPrototype, Deallocator, DeclContext, DefaultArgumentInitializer, DependentAssociatedConformance, DependentAssociatedTypeRef, DependentGenericConformanceRequirement, DependentGenericParamCount,
    DependentGenericParamType, DependentGenericSameTypeRequirement, DependentGenericSameShapeRequirement, DependentGenericLayoutRequirement, DependentGenericParamPackMarker, DependentGenericSignature, DependentGenericType, DependentMemberType,
    DependentPseudogenericSignature, DependentProtocolConformanceRoot, DependentProtocolConformanceInherited, DependentProtocolConformanceAssociated, DependentProtocolConformanceOpaque, Destructor, DidSet, Directness,
    DistributedThunk, DistributedAccessor, DynamicAttribute, DirectMethodReferenceAttribute, DynamicSelf, DynamicallyReplaceableFunctionImpl, DynamicallyReplaceableFunctionKey, DynamicallyReplaceableFunctionVar,
    Enum, EnumCase, ErrorType, EscapingAutoClosureType, NoEscapeFunctionType, ConcurrentFunctionType, GlobalActorFunctionType, DifferentiableFunctionType,
    ExistentialMetatype, ExplicitClosure, Extension, ExtensionAttachedMacroExpansion, FieldOffset, FreestandingMacroExpansion, FullTypeMetadata, Function,
    FunctionSignatureSpecialization, FunctionSignatureSpecializationParam, FunctionSignatureSpecializationReturn, FunctionSignatureSpecializationParamKind, FunctionSignatureSpecializationParamPayload, FunctionType, ConstrainedExistential, ConstrainedExistentialRequirementList,
    ConstrainedExistentialSelf, GenericPartialSpecialization, GenericPartialSpecializationNotReAbstracted, GenericProtocolWitnessTable, GenericProtocolWitnessTableInstantiationFunction, ResilientProtocolWitnessTable, GenericSpecialization, GenericSpecializationNotReAbstracted,
    GenericSpecializationInResilienceDomain, GenericSpecializationParam, GenericSpecializationPrespecialized, InlinedGenericFunction, GenericTypeMetadataPattern, Getter, Global, GlobalGetter,
    Identifier, Index, IVarInitializer, IVarDestroyer, ImplEscaping, ImplConvention, ImplDifferentiabilityKind, ImplNonisolatedNonsendingIsolation,
    ImplErasedIsolation, ImplCalledOnceFunction, ImplSendingResult, ImplParameterResultDifferentiability, ImplParameterSending, ImplParameterIsolated, ImplParameterImplicitLeading, ImplFunctionAttribute,
    ImplFunctionConvention, ImplFunctionConventionName, ImplFunctionType, ImplCoroutineKind, ImplInvocationSubstitutions, ImplicitClosure, ImplParameter, ImplPatternSubstitutions,
    ImplResult, ImplYield, ImplErrorResult, InOut, InfixOperator, Initializer, InitAccessor, Isolated,
    IsolatedDeallocator, Sending, IsolatedAnyFunctionType, NonIsolatedCallerFunctionType, SendingResultFunctionType, KeyPathGetterThunkHelper, KeyPathSetterThunkHelper, KeyPathUnappliedMethodThunkHelper,
    KeyPathAppliedMethodThunkHelper, KeyPathEqualsThunkHelper, KeyPathHashThunkHelper, LazyProtocolWitnessTableAccessor, LazyProtocolWitnessTableCacheVariable, LocalDeclName, Macro, MacroExpansionLoc,
    MacroExpansionUniqueName, MaterializeForSet, MemberAttachedMacroExpansion, MemberAttributeAttachedMacroExpansion, MergedFunction, Metatype, MetatypeRepresentation, Metaclass,
    MethodLookupFunction, ObjCMetadataUpdateFunction, ObjCResilientClassStub, FullObjCResilientClassStub, ModifyAccessor, YieldingMutateAccessor, Module, NativeOwningAddressor,
    NativeOwningMutableAddressor, NativePinningAddressor, NativePinningMutableAddressor, NominalTypeDescriptor, NominalTypeDescriptorRecord, NonObjCAttribute, Number, ObjCAsyncCompletionHandlerImpl,
    CheckedObjCAsyncCompletionHandlerImpl, ObjCAttribute, ObjCBlock, EscapingObjCBlock, OtherNominalType, OwningAddressor, OwningMutableAddressor, PartialApplyForwarder,
    PartialApplyObjCForwarder, PeerAttachedMacroExpansion, PostfixOperator, PreambleAttachedMacroExpansion, PrefixOperator, PrivateDeclName, PropertyDescriptor, PropertyWrapperBackingInitializer,
    PropertyWrappedFieldInitAccessor, PropertyWrapperInitFromProjectedValue, Protocol, ProtocolSymbolicReference, ProtocolConformance, ProtocolConformanceRefInTypeModule, ProtocolConformanceRefInProtocolModule, ProtocolConformanceRefInOtherModule,
    ProtocolDescriptor, ProtocolDescriptorRecord, ProtocolConformanceDescriptor, ProtocolConformanceDescriptorRecord, ProtocolList, ProtocolListWithClass, ProtocolListWithAnyObject, ProtocolSelfConformanceDescriptor,
    ProtocolSelfConformanceWitness, ProtocolSelfConformanceWitnessTable, ProtocolWitness, ProtocolWitnessTable, ProtocolWitnessTableAccessor, ProtocolWitnessTablePattern, ReabstractionThunk, ReabstractionThunkHelper,
    ReabstractionThunkHelperWithSelf, ReabstractionThunkHelperWithGlobalActor, ReadAccessor, YieldingBorrowAccessor, RelatedEntityDeclName, RetroactiveConformance, ReturnType, Shared,
    Owned, SILBoxType, SILBoxTypeWithLayout, SILBoxLayout, SILBoxMutableField, SILBoxImmutableField, Setter, SpecializationPassID,
    IsSerialized, Static, Structure, Subscript, Suffix, ThinFunctionType, Tuple, TupleElement,
    TupleElementName, Pack, SILPackDirect, SILPackIndirect, PackExpansion, PackElement, PackElementLevel, Type,
    TypeSymbolicReference, TypeAlias, TypeList, TypeMangling, TypeMetadata, TypeMetadataAccessFunction, TypeMetadataCompletionFunction, TypeMetadataInstantiationCache,
    TypeMetadataInstantiationFunction, TypeMetadataSingletonInitializationCache, TypeMetadataDemanglingCache, TypeMetadataLazyCache, UncurriedFunctionType, UnknownIndex, UnsafeAddressor, UnsafeMutableAddressor,
    ValueWitness, ValueWitnessTable, Variable, VTableThunk, VTableAttribute, WillSet, ReflectionMetadataBuiltinDescriptor, ReflectionMetadataFieldDescriptor,
    ReflectionMetadataAssocTypeDescriptor, ReflectionMetadataSuperclassDescriptor, GenericTypeParamDecl, CurryThunk, SILThunkIdentity, DispatchThunk, MethodDescriptor, ProtocolRequirementsBaseDescriptor,
    AssociatedConformanceDescriptor, DefaultAssociatedConformanceAccessor, BaseConformanceDescriptor, AssociatedTypeDescriptor, AsyncAnnotation, ThrowsAnnotation, TypedThrowsAnnotation, EmptyList,
    FirstElementMarker, VariadicMarker, OutlinedBridgedMethod, OutlinedCopy, OutlinedConsume, OutlinedRetain, OutlinedRelease, OutlinedInitializeWithTake,
    OutlinedInitializeWithCopy, OutlinedAssignWithTake, OutlinedAssignWithCopy, OutlinedDestroy, OutlinedVariable, OutlinedReadOnlyObject, AssocTypePath, LabelList,
    ModuleDescriptor, ExtensionDescriptor, AnonymousDescriptor, AssociatedTypeGenericParamRef, SugaredOptional, SugaredArray, SugaredDictionary, SugaredInlineArray,
    SugaredParen, AccessorFunctionReference, OpaqueType, OpaqueTypeDescriptorSymbolicReference, OpaqueTypeDescriptor, OpaqueTypeDescriptorRecord, OpaqueTypeDescriptorAccessor, OpaqueTypeDescriptorAccessorImpl,
    OpaqueTypeDescriptorAccessorKey, OpaqueTypeDescriptorAccessorVar, OpaqueReturnType, OpaqueReturnTypeOf, CanonicalSpecializedGenericMetaclass, CanonicalSpecializedGenericTypeMetadataAccessFunction, MetadataInstantiationCache, NoncanonicalSpecializedGenericTypeMetadata,
    NoncanonicalSpecializedGenericTypeMetadataCache, GlobalVariableOnceFunction, GlobalVariableOnceToken, GlobalVariableOnceDeclList, CanonicalPrespecializedGenericTypeCachingOnceToken, AsyncFunctionPointer, AutoDiffFunction, AutoDiffFunctionKind,
    AutoDiffSelfReorderingReabstractionThunk, AutoDiffSubsetParametersThunk, AutoDiffDerivativeVTableThunk, DifferentiabilityWitness, NoDerivative, IndexSubset, AsyncAwaitResumePartialFunction, AsyncSuspendResumePartialFunction,
    AccessibleFunctionRecord, CompileTimeLiteral, BackDeploymentThunk, BackDeploymentFallback, ExtendedExistentialTypeShape, Uniquable, UniqueExtendedExistentialTypeShapeSymbolicReference, NonUniqueExtendedExistentialTypeShapeSymbolicReference,
    SymbolicExtendedExistentialType, DroppedArgument, HasSymbolQuery, OpaqueReturnTypeIndex, OpaqueReturnTypeParent, OutlinedEnumTagStore, OutlinedEnumProjectDataForLoad, OutlinedEnumGetTag,
    AsyncRemoved, RepresentationChanged, ObjectiveCProtocolSymbolicReference, OutlinedInitializeWithTakeNoValueWitness, OutlinedInitializeWithCopyNoValueWitness, OutlinedAssignWithTakeNoValueWitness, OutlinedAssignWithCopyNoValueWitness, OutlinedDestroyNoValueWitness,
    DependentGenericInverseConformanceRequirement, Integer, NegativeInteger, DependentGenericParamValueMarker, CoroFunctionPointer, DefaultOverride, ConstValue, BorrowAccessor,
    MutateAccessor, AsyncMainEntryPoint, CalledOnceFunctionType, YieldTypes, CalledAtMostOnceFunctionType, ImplCalledAtMostOnceFunction, Weak, Unowned,
    Unmanaged,
}
