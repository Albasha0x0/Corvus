# simplify_methods: engine contract

Generated from `SimplifyManifest` (src/NetDecompilerMcp/Services/Simplify/SimplifyManifest.cs); a test keeps the two in sync.

The engine rewrites copies of method bodies and keeps a rewrite only when the result passes the stack verifier. Every
evaluation that leaves the supported subset stops at that point and leaves the code as it was; every skipped rewrite and
every method left unchanged is reported with one of the reasons below.

## Interpreter instructions

| Group | Instructions | Notes |
|---|---|---|
| Constants and stack | `nop` `ldc.i4` `ldc.i4.s` `ldc.i4.m1` `ldc.i4.0` `ldc.i4.1` `ldc.i4.2` `ldc.i4.3` `ldc.i4.4` `ldc.i4.5` `ldc.i4.6` `ldc.i4.7` `ldc.i4.8` `ldc.i8` `ldc.r4` `ldc.r8` `ldnull` `ldstr` `dup` `pop` |  |
| Prefixes | `tail.` `volatile.` `unaligned.` `readonly.` `constrained.` | no effect on the evaluated result; after constrained., callvirt gets the value's address as its receiver |
| Arguments and locals | `ldarg` `ldarg.s` `ldarg.0` `ldarg.1` `ldarg.2` `ldarg.3` `starg` `starg.s` `ldarga` `ldarga.s` `ldloc` `ldloc.s` `ldloc.0` `ldloc.1` `ldloc.2` `ldloc.3` `stloc` `stloc.s` `stloc.0` `stloc.1` `stloc.2` `stloc.3` `ldloca` `ldloca.s` | struct values are copied on load and store; ldarga / ldloca give managed pointers |
| Arithmetic and bit operations | `add` `sub` `mul` `div` `div.un` `rem` `rem.un` `and` `or` `xor` `shl` `shr` `shr.un` `add.ovf` `add.ovf.un` `sub.ovf` `sub.ovf.un` `mul.ovf` `mul.ovf.un` `neg` `not` `ckfinite` | int32, int64 and native int; native int results must be the same on 32- and 64-bit platforms; float32 operands are computed in single precision as the JIT does; division by zero and checked overflow stop evaluation |
| Comparisons | `ceq` `cgt` `cgt.un` `clt` `clt.un` | references compare by identity or against null |
| Conversions | `conv.i1` `conv.i2` `conv.i4` `conv.i8` `conv.u1` `conv.u2` `conv.u4` `conv.u8` `conv.i` `conv.u` `conv.r4` `conv.r8` `conv.r.un` `conv.ovf.i1` `conv.ovf.i2` `conv.ovf.i4` `conv.ovf.i8` `conv.ovf.u1` `conv.ovf.u2` `conv.ovf.u4` `conv.ovf.u8` `conv.ovf.i` `conv.ovf.u` `conv.ovf.i1.un` `conv.ovf.i2.un` `conv.ovf.i4.un` `conv.ovf.i8.un` `conv.ovf.u1.un` `conv.ovf.u2.un` `conv.ovf.u4.un` `conv.ovf.u8.un` `conv.ovf.i.un` `conv.ovf.u.un` | exact ECMA-335 semantics: truncation, sign / zero extension, overflow checks of conv.ovf; out-of-range float to integer conversion (undefined) stops evaluation |
| Branches | `br` `br.s` `brtrue` `brtrue.s` `brfalse` `brfalse.s` `beq` `beq.s` `bne.un` `bne.un.s` `bge` `bge.s` `bge.un` `bge.un.s` `bgt` `bgt.s` `bgt.un` `bgt.un.s` `ble` `ble.s` `ble.un` `ble.un.s` `blt` `blt.s` `blt.un` `blt.un.s` `switch` `ret` | loops run within the shared instruction budget |
| Exception regions | `leave` `leave.s` `endfinally` | try blocks run as plain code and leave runs the finally handlers it exits; nothing is ever caught: code that throws stops evaluation, so catch and fault handlers never run; exception filters are not modelled |
| Arrays | `newarr` `ldlen` `ldelema` `ldelem.i1` `ldelem.u1` `ldelem.i2` `ldelem.u2` `ldelem.i4` `ldelem.u4` `ldelem.i8` `ldelem.i` `ldelem.r4` `ldelem.r8` `ldelem.ref` `ldelem` `stelem.i1` `stelem.i2` `stelem.i4` `stelem.i8` `stelem.i` `stelem.r4` `stelem.r8` `stelem.ref` `stelem` | one-dimensional arrays of primitives, strings and other references; at most 1M elements |
| Stack memory | `localloc` | localloc (stackalloc) gives a zeroed buffer of at most 1M bytes; pointers into it move by add / sub, and ldind / stind read and write it little-endian |
| Indirect access | `ldind.i1` `ldind.u1` `ldind.i2` `ldind.u2` `ldind.i4` `ldind.u4` `ldind.i8` `ldind.i` `ldind.r4` `ldind.r8` `ldind.ref` `stind.i1` `stind.i2` `stind.i4` `stind.i8` `stind.i` `stind.r4` `stind.r8` `stind.ref` | through managed pointers to arguments, locals, array elements, struct fields and static fields, and through pointers into stack memory |
| Objects and value types | `ldobj` `stobj` `initobj` `ldfld` `ldflda` `stfld` | structs defined in the same module (sequential or auto layout), enums and primitives; instances of the module's classes (see unmodeled-instance) created by the evaluated code, with their fields, constructors, and instance and virtual methods dispatched within the module; new object(); a field of a class that nothing in the module writes (and no other assembly can) reads as its default on every object, which folds conditions on it even where the object itself cannot be evaluated (the load is kept: it still throws on null) |
| Static state | `ldsfld` `ldsflda` `stsfld` `ldtoken` | static fields of the same module that are readonly, or that only the type's initialization writes and other assemblies cannot, after evaluating the type's static constructor once; an instance with no fields held there (a lambda class's singleton) cannot change, so any code may read it; writes only inside static constructors (by stsfld or FieldInfo.SetValue); ldtoken of fields, types and methods |
| Collections |  | Dictionary<K, V> (keys: numbers and strings) and List<T>: construction, Add, indexers, TryGetValue, ContainsKey, Remove, Count, Clear, Contains, IndexOf, Insert, RemoveAt, ToArray, and foreach over them in the order of addition (a dictionary after a removal is not enumerated); Monitor.Enter / Exit (lock) succeed at once. A static collection the code only uses through its own methods, written only by its type's initialization, counts as a cache: each evaluation starts from the state the initialization left, and the call made again on the state it leaves must give the same result (see cache-dependent) |
| Resources and streams |  | the module's own embedded resources: Assembly.GetManifestResourceNames and GetManifestResourceStream (the executing, calling or a type's own assembly); read-only streams over them or over byte arrays (MemoryStream): Read, ReadByte, Length, Position, Seek, Close; BinaryReader (bytes, integers, floats, strings with a 7-bit length) and StreamReader (UTF-8 or an explicit encoding, byte-order marks detected as the CLR does) over them. The same resource reads the same bytes on every run; its bytes count against the simulated memory |
| Boxing | `box` `unbox` `unbox.any` | box gives an immutable object holding the value (box of a reference, as for a type argument that is a class, leaves it as it is); unbox.any and unbox take the value back out of a box of the same type, or of an enum and its underlying integer type; unbox.any of a reference type is castclass; Nullable<T> is not boxed |
| Sizes | `sizeof` | sizeof of primitive and enum types; native-size types differ between platforms |
| Type tests | `isinst` `castclass` | System.Object, System.String, System.Text.StringBuilder and System.Text.Encoding targets |
| Calls | `call` `callvirt` `newobj` `ldftn` | intrinsics (below), and static methods and struct methods with IL bodies in the same module; static generic methods of the module with closed type arguments (!!n in parameter, local and operand types replaced by the instantiation's); newobj of strings, StringBuilder and module structs; delegates of static methods (ldftn and the delegate constructor, Delegate.CreateDelegate) and of instance methods bound to an instance with no fields and of dynamic methods, invoked through Invoke |

Every other instruction stops evaluation with `unsupported-instruction`.

## Intrinsics

Framework methods evaluated directly (deterministic and culture-independent for the values they accept):

- `System.Array System.Array::CreateInstance(System.Type,System.Int32)`
- `System.Boolean System.Reflection.MethodBase::get_IsStatic()`
- `System.Boolean System.String::Equals(System.String)`
- `System.Boolean System.String::Equals(System.String,System.String)`
- `System.Boolean System.String::IsNullOrEmpty(System.String)`
- `System.Boolean System.String::op_Equality(System.String,System.String)`
- `System.Boolean System.String::op_Inequality(System.String,System.String)`
- `System.Boolean System.Type::op_Equality(System.Type,System.Type)`
- `System.Boolean System.Type::op_Inequality(System.Type,System.Type)`
- `System.Byte System.Convert::ToByte(System.Int32)`
- `System.Byte[] System.Convert::FromBase64String(System.String)`
- `System.Byte[] System.Security.Cryptography.Aes::get_IV()`
- `System.Byte[] System.Security.Cryptography.Aes::get_Key()`
- `System.Byte[] System.Security.Cryptography.AesCryptoServiceProvider::get_IV()`
- `System.Byte[] System.Security.Cryptography.AesCryptoServiceProvider::get_Key()`
- `System.Byte[] System.Security.Cryptography.AesManaged::get_IV()`
- `System.Byte[] System.Security.Cryptography.AesManaged::get_Key()`
- `System.Byte[] System.Security.Cryptography.DES::get_IV()`
- `System.Byte[] System.Security.Cryptography.DES::get_Key()`
- `System.Byte[] System.Security.Cryptography.DESCryptoServiceProvider::get_IV()`
- `System.Byte[] System.Security.Cryptography.DESCryptoServiceProvider::get_Key()`
- `System.Byte[] System.Security.Cryptography.ICryptoTransform::TransformFinalBlock(System.Byte[],System.Int32,System.Int32)`
- `System.Byte[] System.Security.Cryptography.Rijndael::get_IV()`
- `System.Byte[] System.Security.Cryptography.Rijndael::get_Key()`
- `System.Byte[] System.Security.Cryptography.RijndaelManaged::get_IV()`
- `System.Byte[] System.Security.Cryptography.RijndaelManaged::get_Key()`
- `System.Byte[] System.Security.Cryptography.SymmetricAlgorithm::get_IV()`
- `System.Byte[] System.Security.Cryptography.SymmetricAlgorithm::get_Key()`
- `System.Byte[] System.Text.Encoding::GetBytes(System.String)`
- `System.Char System.Convert::ToChar(System.Int32)`
- `System.Char System.String::get_Chars(System.Int32)`
- `System.Char System.Text.StringBuilder::get_Chars(System.Int32)`
- `System.Char[] System.String::ToCharArray()`
- `System.Delegate System.Delegate::CreateDelegate(System.Type,System.Reflection.MethodInfo)`
- `System.Delegate System.Reflection.Emit.DynamicMethod::CreateDelegate(System.Type)`
- `System.Delegate System.Reflection.MethodInfo::CreateDelegate(System.Type)`
- `System.Int32 System.Array::get_Length()`
- `System.Int32 System.Convert::ToInt32(System.Byte)`
- `System.Int32 System.Convert::ToInt32(System.Char)`
- `System.Int32 System.Convert::ToInt32(System.Int16)`
- `System.Int32 System.Convert::ToInt32(System.Int64)`
- `System.Int32 System.Convert::ToInt32(System.String)`
- `System.Int32 System.Convert::ToInt32(System.UInt32)`
- `System.Int32 System.Math::Abs(System.Int32)`
- `System.Int32 System.Math::Max(System.Int32,System.Int32)`
- `System.Int32 System.Math::Min(System.Int32,System.Int32)`
- `System.Int32 System.Reflection.MemberInfo::get_MetadataToken()`
- `System.Int32 System.Security.Cryptography.Aes::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.AesCryptoServiceProvider::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.AesManaged::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.DES::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.DESCryptoServiceProvider::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.ICryptoTransform::get_InputBlockSize()`
- `System.Int32 System.Security.Cryptography.ICryptoTransform::get_OutputBlockSize()`
- `System.Int32 System.Security.Cryptography.Rijndael::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.RijndaelManaged::get_BlockSize()`
- `System.Int32 System.Security.Cryptography.SymmetricAlgorithm::get_BlockSize()`
- `System.Int32 System.String::IndexOf(System.Char)`
- `System.Int32 System.String::get_Length()`
- `System.Int32 System.Text.StringBuilder::get_Length()`
- `System.Int64 System.Convert::ToInt64(System.Int32)`
- `System.ModuleHandle System.Reflection.Module::get_ModuleHandle()`
- `System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()`
- `System.Reflection.Emit.ILGenerator System.Reflection.Emit.DynamicMethod::GetILGenerator()`
- `System.Reflection.FieldInfo System.Reflection.FieldInfo::GetFieldFromHandle(System.RuntimeFieldHandle)`
- `System.Reflection.FieldInfo System.Reflection.Module::ResolveField(System.Int32)`
- `System.Reflection.FieldInfo System.Type::GetField(System.String)`
- `System.Reflection.FieldInfo System.Type::GetField(System.String,System.Reflection.BindingFlags)`
- `System.Reflection.FieldInfo[] System.Type::GetFields(System.Reflection.BindingFlags)`
- `System.Reflection.MethodBase System.Reflection.MethodBase::GetMethodFromHandle(System.RuntimeMethodHandle)`
- `System.Reflection.MethodBase System.Reflection.Module::ResolveMethod(System.Int32)`
- `System.Reflection.MethodInfo System.Type::GetMethod(System.String)`
- `System.Reflection.MethodInfo System.Type::GetMethod(System.String,System.Reflection.BindingFlags)`
- `System.Reflection.MethodInfo[] System.Type::GetMethods(System.Reflection.BindingFlags)`
- `System.Reflection.Module System.Reflection.Assembly::get_ManifestModule()`
- `System.Reflection.Module System.Type::get_Module()`
- `System.Reflection.Module[] System.Reflection.Assembly::GetModules()`
- `System.Reflection.ParameterInfo[] System.Reflection.MethodBase::GetParameters()`
- `System.RuntimeFieldHandle System.ModuleHandle::GetRuntimeFieldHandleFromMetadataToken(System.Int32)`
- `System.RuntimeFieldHandle System.ModuleHandle::ResolveFieldHandle(System.Int32)`
- `System.RuntimeMethodHandle System.ModuleHandle::GetRuntimeMethodHandleFromMetadataToken(System.Int32)`
- `System.RuntimeMethodHandle System.ModuleHandle::ResolveMethodHandle(System.Int32)`
- `System.RuntimeTypeHandle System.ModuleHandle::GetRuntimeTypeHandleFromMetadataToken(System.Int32)`
- `System.RuntimeTypeHandle System.ModuleHandle::ResolveTypeHandle(System.Int32)`
- `System.RuntimeTypeHandle System.Type::get_TypeHandle()`
- `System.Security.Cryptography.Aes System.Security.Cryptography.Aes::Create()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.Aes::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.AesCryptoServiceProvider::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.AesManaged::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.DES::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.DESCryptoServiceProvider::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.Rijndael::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.RijndaelManaged::get_Mode()`
- `System.Security.Cryptography.CipherMode System.Security.Cryptography.SymmetricAlgorithm::get_Mode()`
- `System.Security.Cryptography.DES System.Security.Cryptography.DES::Create()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Aes::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Aes::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Aes::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Aes::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesCryptoServiceProvider::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesCryptoServiceProvider::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesCryptoServiceProvider::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesCryptoServiceProvider::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesManaged::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesManaged::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesManaged::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.AesManaged::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DES::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DES::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DES::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DES::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DESCryptoServiceProvider::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DESCryptoServiceProvider::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DESCryptoServiceProvider::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.DESCryptoServiceProvider::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Rijndael::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Rijndael::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Rijndael::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.Rijndael::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.RijndaelManaged::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.RijndaelManaged::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.RijndaelManaged::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.RijndaelManaged::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.SymmetricAlgorithm::CreateEncryptor()`
- `System.Security.Cryptography.ICryptoTransform System.Security.Cryptography.SymmetricAlgorithm::CreateEncryptor(System.Byte[],System.Byte[])`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.Aes::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.AesCryptoServiceProvider::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.AesManaged::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.DES::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.DESCryptoServiceProvider::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.Rijndael::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.RijndaelManaged::get_Padding()`
- `System.Security.Cryptography.PaddingMode System.Security.Cryptography.SymmetricAlgorithm::get_Padding()`
- `System.Security.Cryptography.Rijndael System.Security.Cryptography.Rijndael::Create()`
- `System.String System.Char::ToString()`
- `System.String System.Char::ToString(System.Char)`
- `System.String System.Convert::ToBase64String(System.Byte[])`
- `System.String System.Int32::ToString()`
- `System.String System.Object::ToString()`
- `System.String System.Reflection.MemberInfo::get_Name()`
- `System.String System.String::Concat(System.Object,System.Object)`
- `System.String System.String::Concat(System.Object,System.Object,System.Object)`
- `System.String System.String::Concat(System.String,System.String)`
- `System.String System.String::Concat(System.String,System.String,System.String)`
- `System.String System.String::Concat(System.String,System.String,System.String,System.String)`
- `System.String System.String::Concat(System.String[])`
- `System.String System.String::Insert(System.Int32,System.String)`
- `System.String System.String::Intern(System.String)`
- `System.String System.String::Join(System.String,System.String[])`
- `System.String System.String::Remove(System.Int32)`
- `System.String System.String::Remove(System.Int32,System.Int32)`
- `System.String System.String::Replace(System.Char,System.Char)`
- `System.String System.String::Replace(System.String,System.String)`
- `System.String System.String::Substring(System.Int32)`
- `System.String System.String::Substring(System.Int32,System.Int32)`
- `System.String System.String::ToLowerInvariant()`
- `System.String System.String::ToUpperInvariant()`
- `System.String System.String::Trim()`
- `System.String System.Text.Encoding::GetString(System.Byte[])`
- `System.String System.Text.Encoding::GetString(System.Byte[],System.Int32,System.Int32)`
- `System.String System.Text.StringBuilder::ToString()`
- `System.StringComparer System.StringComparer::get_Ordinal()`
- `System.StringComparer System.StringComparer::get_OrdinalIgnoreCase()`
- `System.Text.Encoding System.Text.Encoding::get_ASCII()`
- `System.Text.Encoding System.Text.Encoding::get_BigEndianUnicode()`
- `System.Text.Encoding System.Text.Encoding::get_UTF8()`
- `System.Text.Encoding System.Text.Encoding::get_Unicode()`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.Char)`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.Char[])`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.Int32)`
- `System.Text.StringBuilder System.Text.StringBuilder::Append(System.String)`
- `System.Text.StringBuilder System.Text.StringBuilder::Insert(System.Int32,System.String)`
- `System.Type System.Reflection.FieldInfo::get_FieldType()`
- `System.Type System.Reflection.MethodInfo::get_ReturnType()`
- `System.Type System.Reflection.Module::ResolveType(System.Int32)`
- `System.Type System.Reflection.ParameterInfo::get_ParameterType()`
- `System.Type System.Type::GetElementType()`
- `System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)`
- `System.Void System.Array::Copy(System.Array,System.Array,System.Int32)`
- `System.Void System.Array::Copy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)`
- `System.Void System.Array::Reverse(System.Array)`
- `System.Void System.Buffer::BlockCopy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)`
- `System.Void System.IDisposable::Dispose()`
- `System.Void System.Reflection.Emit.DynamicMethod::.ctor(System.String,System.Type,System.Type[])`
- `System.Void System.Reflection.Emit.DynamicMethod::.ctor(System.String,System.Type,System.Type[],System.Boolean)`
- `System.Void System.Reflection.Emit.DynamicMethod::.ctor(System.String,System.Type,System.Type[],System.Reflection.Module)`
- `System.Void System.Reflection.Emit.DynamicMethod::.ctor(System.String,System.Type,System.Type[],System.Reflection.Module,System.Boolean)`
- `System.Void System.Reflection.Emit.DynamicMethod::.ctor(System.String,System.Type,System.Type[],System.Type)`
- `System.Void System.Reflection.Emit.DynamicMethod::.ctor(System.String,System.Type,System.Type[],System.Type,System.Boolean)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Byte)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Int16)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Int32)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Int64)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Reflection.ConstructorInfo)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Reflection.FieldInfo)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Reflection.MethodInfo)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.SByte)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.String)`
- `System.Void System.Reflection.Emit.ILGenerator::Emit(System.Reflection.Emit.OpCode,System.Type)`
- `System.Void System.Reflection.FieldInfo::SetValue(System.Object,System.Object)`
- `System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)`
- `System.Void System.Security.Cryptography.Aes::Clear()`
- `System.Void System.Security.Cryptography.Aes::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.Aes::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.Aes::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.Aes::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.Aes::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.Aes::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::.ctor()`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::Clear()`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.AesCryptoServiceProvider::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.AesManaged::.ctor()`
- `System.Void System.Security.Cryptography.AesManaged::Clear()`
- `System.Void System.Security.Cryptography.AesManaged::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.AesManaged::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.AesManaged::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.AesManaged::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.AesManaged::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.AesManaged::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.DES::Clear()`
- `System.Void System.Security.Cryptography.DES::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.DES::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.DES::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.DES::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.DES::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.DES::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::.ctor()`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::Clear()`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.DESCryptoServiceProvider::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.Rijndael::Clear()`
- `System.Void System.Security.Cryptography.Rijndael::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.Rijndael::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.Rijndael::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.Rijndael::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.Rijndael::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.Rijndael::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.RijndaelManaged::.ctor()`
- `System.Void System.Security.Cryptography.RijndaelManaged::Clear()`
- `System.Void System.Security.Cryptography.RijndaelManaged::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.RijndaelManaged::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.RijndaelManaged::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.RijndaelManaged::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.RijndaelManaged::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.RijndaelManaged::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::Clear()`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::set_BlockSize(System.Int32)`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::set_IV(System.Byte[])`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::set_Key(System.Byte[])`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::set_KeySize(System.Int32)`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::set_Mode(System.Security.Cryptography.CipherMode)`
- `System.Void System.Security.Cryptography.SymmetricAlgorithm::set_Padding(System.Security.Cryptography.PaddingMode)`
- `System.Void System.String::.ctor(System.Char,System.Int32)`
- `System.Void System.String::.ctor(System.Char[])`
- `System.Void System.String::.ctor(System.Char[],System.Int32,System.Int32)`
- `System.Void System.Text.StringBuilder::.ctor()`
- `System.Void System.Text.StringBuilder::.ctor(System.Int32)`
- `System.Void System.Text.StringBuilder::.ctor(System.String)`
- `System.Void System.Text.StringBuilder::set_Length(System.Int32)`
- `System.Void System.Threading.Monitor::Enter(System.Object)`
- `System.Void System.Threading.Monitor::Enter(System.Object,System.Boolean&)`
- `System.Void System.Threading.Monitor::Exit(System.Object)`

## Limits

| Limit | Default |
|---|---|
| maxDepth | 8 frames, the evaluated call included (tool parameter, 1-64) |
| budget | 100,000 instructions per evaluation, shared by nested calls and the static constructors they trigger (tool parameter) |
| method budget | 5,000,000 instructions across all evaluations of one method |
| memory | 16 MB of simulated allocations per evaluation, static state included |
| time | 5 s per method, all passes included |
| arrays and strings | 1M elements / characters |

## Fallback reasons

| Code | Meaning |
|---|---|
| `unsupported-instruction` | an IL instruction that is not in the instruction table below |
| `unsupported-call` | a call to a framework or other method that is neither an intrinsic nor IL of the same module (I/O, reflection, threading, ...) |
| `no-body` | the callee has no IL body: P/Invoke, internal call, runtime-implemented or abstract |
| `other-module` | the callee or a static field belongs to another module, whose code may differ at run time |
| `generic` | a generic method of another module or an instance generic method, a member of a generic type, or a type argument that is not a closed type |
| `exception-handling` | the callee has exception handlers, or the code throws |
| `instance-object` | uses an object the evaluation did not create (an instance passed in from outside, or a delegate bound to an object) or calls an instance method on such an object |
| `unsupported-value` | a value the interpreter does not model: Nullable<T> boxes, unboxing as another type, unmanaged pointers, typed references, structs of other modules or with explicit layout, arrays of structs, type tokens |
| `mutable-static` | reads a static field that is not readonly, writes a static field outside a static constructor, or modifies an object held in a static field |
| `unmodeled-instance` | creates an instance of a class outside the modelled subset: a class with a finalizer or events, a generic class, a class whose base class belongs to another assembly (exceptions, framework classes), an interop class (COM import, explicit layout), or a hierarchy deeper than 8 levels |
| `virtual-dispatch` | a call on a modelled instance that does not resolve to one method of the module: a framework method or the framework implementation of a virtual method (ToString, Equals, ...), an abstract method, or an interface method the class does not implement in the module |
| `cache-dependent` | a static Dictionary or List the code reads is not a cache whose contents cannot change the result: called again on the state the first call left, the call gives another result; or the collection is used other than through its own methods (passed on, stored, returned, its address taken), is visible to other assemblies, is written outside its type's initialization, or compares keys with a custom comparer |
| `writable-stream` | writes to a stream (Write, WriteByte, SetLength, Flush, CopyTo) or creates an empty MemoryStream to write into; the evaluator only reads streams |
| `external-io` | reads what differs between runs or machines: files (File, FileStream, Directory, StreamReader over a path), the network (System.Net), another assembly's resources, or the entry assembly |
| `static-initializer` | the static constructor of a type the code needs cannot be evaluated, or the code can run while it runs. Inside that static constructor itself, a call uses the state as it stands at the call when the constructor reaches the call at most once (on no loop, in no handler) and runs up to it; otherwise it is kept |
| `runtime-error` | the code would throw at run time: division by zero, checked overflow, index out of range, null reference, invalid cast, invalid argument |
| `platform-dependent` | the result would differ between platforms or cultures: native int values outside the 32-bit range, out-of-range float to integer conversion, culture-sensitive formatting |
| `invalid-code` | the evaluated code is not valid IL: stack underflow, mismatched operand types, a branch outside the method, execution past its end |
| `call-depth` | nested calls exceed the depth limit (maxDepth) (resource limit) |
| `instruction-budget` | the evaluation, including nested calls and static constructors, executed more instructions than the budget allows, or the method's total budget ran out (resource limit) |
| `memory-limit` | the evaluation allocated more simulated memory (arrays, strings, builders) than the limit (resource limit) |
| `time-limit` | simplifying the method took longer than its time limit; the method is left unchanged (resource limit) |
| `flattened-shape` | flattened control flow (a loop over a switch on a state) whose dispatcher cannot be removed: run through per state, some way into it does not select the same case on every run (the state depends on arguments or other unknown values, or on the path taken), a case reads the state with a value that depends on the path taken, the state's address is taken, the dispatcher or a case is in another protected region, or the analysis exceeds its limits (1,024 states); the dispatcher is kept as it is and the other passes still apply to the method |
| `delegate-target` | a call through a static delegate field whose target is not known to be the same on every run: the field is written outside its type's initialization or is accessible to other assemblies, the initialization cannot be evaluated (the message says why), the delegate is bound to an object other than a field-less instance that a static field accessible at the call holds, or calls an instance method directly, its dynamic method does more than pass its arguments on, or the delegate is not loaded right before its arguments; the call is kept |
| `original-unverifiable` | the original body does not pass the stack verifier, so it is not rewritten |
| `unreadable-bodies` | a quarter or more of the module's method bodies cannot be read as IL: they are stored in another form on disk and restored at run time (an integrity check). Bodies that happen to decode are not the code that runs, and a rewritten image would not run, so no method of the module is rewritten |
| `result-unverifiable` | the rewritten body did not pass the stack verifier; the method is left unchanged |
| `unexpected` | an unexpected error while reading or rewriting the body (malformed metadata or a defect); the method is left unchanged |
