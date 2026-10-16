namespace Corvus.Native.Dwarf;

/// <summary>The DW_TAG, DW_AT, DW_FORM and DW_ATE values the reader uses (DWARF 2-5 and the GNU extensions compilers emit).</summary>
internal static class Dw
{
    public const int TagArrayType = 0x01, TagClassType = 0x02, TagEnumerationType = 0x04, TagFormalParameter = 0x05, TagLexicalBlock = 0x0b,
        TagMember = 0x0d, TagPointerType = 0x0f, TagReferenceType = 0x10, TagCompileUnit = 0x11, TagStructureType = 0x13, TagSubroutineType = 0x15,
        TagTypedef = 0x16, TagUnionType = 0x17, TagUnspecifiedParameters = 0x18, TagVariant = 0x19, TagInheritance = 0x1c, TagInlinedSubroutine = 0x1d,
        TagPtrToMemberType = 0x1f, TagSubrangeType = 0x21, TagBaseType = 0x24, TagConstType = 0x26, TagEnumerator = 0x28, TagSubprogram = 0x2e,
        TagVariable = 0x34, TagVolatileType = 0x35, TagRestrictType = 0x37, TagNamespace = 0x39, TagUnspecifiedType = 0x3b, TagPartialUnit = 0x3c,
        TagTypeUnit = 0x41, TagRvalueReferenceType = 0x42, TagTemplateAlias = 0x43, TagAtomicType = 0x47, TagSkeletonUnit = 0x4a, TagImmutableType = 0x4b;

    public const int AtLocation = 0x02, AtName = 0x03, AtByteSize = 0x0b, AtBitOffset = 0x0c, AtBitSize = 0x0d, AtStmtList = 0x10, AtLowPc = 0x11,
        AtHighPc = 0x12, AtLanguage = 0x13, AtCompDir = 0x1b, AtConstValue = 0x1c, AtLowerBound = 0x22, AtUpperBound = 0x2f, AtAbstractOrigin = 0x31,
        AtCount = 0x37, AtDataMemberLocation = 0x38, AtDeclFile = 0x3a, AtDeclLine = 0x3b, AtDeclaration = 0x3c, AtEncoding = 0x3e, AtExternal = 0x3f,
        AtSpecification = 0x47, AtType = 0x49, AtVirtuality = 0x4c, AtEntryPc = 0x52, AtRanges = 0x55, AtCallFile = 0x58, AtCallLine = 0x59,
        AtArtificial = 0x34, AtSignature = 0x69, AtDataBitOffset = 0x6b, AtLinkageName = 0x6e, AtStrOffsetsBase = 0x72, AtAddrBase = 0x73,
        AtRnglistsBase = 0x74, AtMipsLinkageName = 0x2007, AtGnuAddrBase = 0x2133, AtGnuRangesBase = 0x2132, AtDwoName = 0x76, AtGnuDwoName = 0x2130, AtGnuDwoId = 0x2131;

    public const int FormAddr = 0x01, FormBlock2 = 0x03, FormBlock4 = 0x04, FormData2 = 0x05, FormData4 = 0x06, FormData8 = 0x07, FormString = 0x08,
        FormBlock = 0x09, FormBlock1 = 0x0a, FormData1 = 0x0b, FormFlag = 0x0c, FormSdata = 0x0d, FormStrp = 0x0e, FormUdata = 0x0f, FormRefAddr = 0x10,
        FormRef1 = 0x11, FormRef2 = 0x12, FormRef4 = 0x13, FormRef8 = 0x14, FormRefUdata = 0x15, FormIndirect = 0x16, FormSecOffset = 0x17,
        FormExprloc = 0x18, FormFlagPresent = 0x19, FormStrx = 0x1a, FormAddrx = 0x1b, FormRefSup4 = 0x1c, FormStrpSup = 0x1d, FormData16 = 0x1e,
        FormLineStrp = 0x1f, FormRefSig8 = 0x20, FormImplicitConst = 0x21, FormLoclistx = 0x22, FormRnglistx = 0x23, FormRefSup8 = 0x24,
        FormStrx1 = 0x25, FormStrx2 = 0x26, FormStrx3 = 0x27, FormStrx4 = 0x28, FormAddrx1 = 0x29, FormAddrx2 = 0x2a, FormAddrx3 = 0x2b,
        FormAddrx4 = 0x2c, FormGnuAddrIndex = 0x1f01, FormGnuStrIndex = 0x1f02, FormGnuRefAlt = 0x1f20, FormGnuStrpAlt = 0x1f21;

    public const int AteAddress = 0x1, AteBoolean = 0x2, AteFloat = 0x4, AteSigned = 0x5, AteSignedChar = 0x6, AteUnsigned = 0x7, AteUnsignedChar = 0x8,
        AteUtf = 0x10;

    public const int UtCompile = 0x01, UtType = 0x02, UtPartial = 0x03, UtSkeleton = 0x04, UtSplitCompile = 0x05, UtSplitType = 0x06;

    public static bool IsUnit(int tag) => tag is TagCompileUnit or TagPartialUnit or TagTypeUnit or TagSkeletonUnit;

    public static bool IsAggregate(int tag) => tag is TagStructureType or TagClassType or TagUnionType;

    /// <summary>Tags whose name scopes nested names ("ns::Outer::inner").</summary>
    public static bool IsScope(int tag) => tag is TagNamespace or TagStructureType or TagClassType or TagUnionType or TagEnumerationType;
}
