using dnlib.DotNet;

namespace Corvus.Services.Simplify;

/// <summary>Generic method instantiations: method type parameters (!!n) replaced by the arguments of the instantiation.</summary>
internal static class Generics
{
    /// <summary>
    /// <paramref name="sig"/> with !!n replaced by <paramref name="methodArgs"/>[n] (custom modifiers and pinned dropped);
    /// unchanged when there are no arguments. A type parameter of a type (!n) stays as it is.
    /// </summary>
    public static TypeSig? Substitute(TypeSig? sig, IList<TypeSig>? methodArgs)
    {
        if (sig == null || methodArgs == null || methodArgs.Count == 0) return sig;
        return Walk(sig.RemovePinnedAndModifiers(), methodArgs, 0);
    }

    private static TypeSig? Walk(TypeSig? sig, IList<TypeSig> args, int depth)
    {
        if (sig == null || depth > 32) return sig;
        sig = sig.RemovePinnedAndModifiers();
        return sig switch
        {
            GenericMVar mvar => mvar.Number < args.Count ? args[(int)mvar.Number] : sig,
            SZArraySig a => new SZArraySig(Walk(a.Next, args, depth + 1)),
            ArraySig a => new ArraySig(Walk(a.Next, args, depth + 1), a.Rank, a.Sizes, a.LowerBounds),
            ByRefSig r => new ByRefSig(Walk(r.Next, args, depth + 1)),
            PtrSig p => new PtrSig(Walk(p.Next, args, depth + 1)),
            GenericInstSig g => new GenericInstSig(g.GenericType, g.GenericArguments.Select(t => Walk(t, args, depth + 1)!).ToList()),
            _ => sig,
        };
    }

    /// <summary>Whether the signature still names a type parameter (!n or !!n).</summary>
    public static bool IsOpen(TypeSig? sig) => sig?.RemovePinnedAndModifiers() switch
    {
        null => false,
        GenericSig => true,
        GenericInstSig g => g.GenericArguments.Any(IsOpen),
        { Next: { } next } => IsOpen(next),
        _ => false,
    };

    /// <summary>The type arguments of a generic method instantiation, or null for a method that is not one.</summary>
    public static IList<TypeSig>? Arguments(IMethod method) => (method as MethodSpec)?.GenericInstMethodSig?.GenericArguments;

    /// <summary>The return type of a call, with the instantiation's arguments substituted.</summary>
    public static TypeSig? ReturnType(IMethod method) => Substitute(method.MethodSig?.RetType, Arguments(method));

    /// <summary>The method an instantiation instantiates, or the method itself.</summary>
    public static IMethod Definition(IMethod method) => method is MethodSpec { Method: { } m } ? m : method;
}
