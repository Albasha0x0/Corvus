// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): exception-heavy control flow -
// nested try/catch/finally, exception filters, rethrow vs throw ex, custom exceptions with properties, finally on
// return/break/continue, exceptions crossing frames, catch order, dispose order, checked overflow and
// AggregateException flattening; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Exceptions
{
    class ValidationException : Exception
    {
        public int Code { get; private set; }
        public string Field { get; private set; }

        public ValidationException(string field, int code) : base("invalid " + field)
        {
            Field = field;
            Code = code;
        }
    }

    sealed class RangeValidationException : ValidationException
    {
        public int Min { get; private set; }
        public int Max { get; private set; }
        public int Actual { get; private set; }

        public RangeValidationException(string field, int min, int max, int actual)
            : base(field, 400 + Math.Abs(actual) % 10)
        {
            Min = min;
            Max = max;
            Actual = actual;
        }
    }

    sealed class PipelineException : Exception
    {
        public int Stage { get; private set; }

        public PipelineException(int stage, string message, Exception inner) : base(message, inner)
        {
            Stage = stage;
        }
    }

    sealed class Tracker : IDisposable
    {
        readonly string name;
        readonly List<string> log;

        public Tracker(string name, List<string> log)
        {
            this.name = name;
            this.log = log;
            log.Add("open " + name);
        }

        public void Dispose()
        {
            log.Add("close " + name);
        }
    }

    static class Program
    {
        static int checksum = 17;

        static void Out(string s)
        {
            Console.WriteLine(s);
            foreach (char c in s)
                checksum = unchecked(checksum * 31 + c);
        }

        static string Describe(Exception e)
        {
            // Custom types may be renamed by the transformation, so describe them by their data.
            var r = e as RangeValidationException;
            if (r != null)
                return string.Format(CultureInfo.InvariantCulture, "range[{0}..{1}] actual={2} code={3} msg={4}", r.Min, r.Max, r.Actual, r.Code, r.Message);
            var v = e as ValidationException;
            if (v != null)
                return string.Format(CultureInfo.InvariantCulture, "validation field={0} code={1} msg={2}", v.Field, v.Code, v.Message);
            var p = e as PipelineException;
            if (p != null)
                return "pipeline stage=" + p.Stage.ToString(CultureInfo.InvariantCulture) + " msg=" + p.Message + " inner=(" + (p.InnerException == null ? "none" : Describe(p.InnerException)) + ")";
            return "builtin " + Kind(e);
        }

        static string Kind(Exception e)
        {
            // A stable code per framework type; type names are never printed.
            if (e is KeyNotFoundException) return "E-key";
            if (e is IndexOutOfRangeException) return "E-index";
            if (e is InvalidCastException) return "E-cast";
            if (e is NotSupportedException) return "E-notsup";
            if (e is InvalidOperationException) return "E-invop";
            if (e is FormatException) return "E-format";
            if (e is ArgumentException) return "E-arg";
            if (e is ArithmeticException) return "E-arith";
            return "E-other";
        }

        static bool Note(StringBuilder sb, string s)
        {
            sb.Append(s);
            return true;
        }

        static string NestedOrder(int mode)
        {
            var sb = new StringBuilder();
            try
            {
                sb.Append("a");
                try
                {
                    sb.Append("b");
                    if (mode == 1) throw new InvalidOperationException("inner");
                    if (mode == 2) throw new ValidationException("name", 7);
                    sb.Append("c");
                }
                catch (InvalidOperationException)
                {
                    sb.Append("d");
                    if (mode == 1) throw new ValidationException("again", 9);
                }
                finally
                {
                    sb.Append("e");
                }
                sb.Append("f");
            }
            catch (ValidationException v)
            {
                sb.Append("g").Append(v.Code);
            }
            finally
            {
                sb.Append("h");
            }
            return sb.ToString();
        }

        static string FilterOrder(int code)
        {
            var sb = new StringBuilder();
            try
            {
                try
                {
                    sb.Append("T");
                    throw new ValidationException("x", code);
                }
                finally
                {
                    sb.Append("F");
                }
            }
            catch (ValidationException e) when (Note(sb, "W1") && e.Code > 500)
            {
                sb.Append("C1");
            }
            catch (ValidationException e) when (Note(sb, "W2") && e.Code % 2 == 0)
            {
                sb.Append("C2");
            }
            catch (Exception)
            {
                sb.Append("C3");
            }
            return sb.ToString();
        }

        static int finallyCounter;

        static int ReturnThroughFinally(int x)
        {
            try
            {
                if (x > 5) return x * 2;
                return -x;
            }
            finally
            {
                finallyCounter += x;
            }
        }

        static string LoopWithFinally()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    if (i % 3 == 0) continue;
                    if (i == 8) break;
                    sb.Append(i);
                }
                finally
                {
                    sb.Append('.');
                }
            }
            return sb.ToString();
        }

        static int Descend(int depth, List<string> trail)
        {
            try
            {
                if (depth == 0)
                    throw new RangeValidationException("depth", 1, 10, depth - 3);
                if (depth == 3)
                {
                    try
                    {
                        return Descend(depth - 1, trail) + 1;
                    }
                    catch (ValidationException v)
                    {
                        throw new PipelineException(depth, "wrapped at " + depth, v);
                    }
                }
                return Descend(depth - 1, trail) + 1;
            }
            finally
            {
                trail.Add("f" + depth);
            }
        }

        static Exception Rethrow(bool preserve)
        {
            var original = new ValidationException("rethrow", preserve ? 1 : 2);
            try
            {
                try
                {
                    throw original;
                }
                catch (ValidationException ex)
                {
                    if (preserve) throw;
                    throw ex;
                }
            }
            catch (Exception caught)
            {
                Out("rethrow preserve=" + preserve + " same=" + ReferenceEquals(caught, original) + " " + Describe(caught));
                return caught;
            }
        }

        static void Raise(int kind)
        {
            switch (kind)
            {
                case 0: throw new ArgumentNullException("p");
                case 1: throw new ArgumentOutOfRangeException("p");
                case 2: throw new ArgumentException("bad argument");
                case 3: throw new RangeValidationException("v", 0, 5, 13);
                case 4: throw new ValidationException("w", 44);
                case 5: throw new KeyNotFoundException("missing");
                case 6: { int[] a = new int[2]; a[kind] = 1; break; }
                case 7: { object o = "text"; int n = (int)o; Out("never " + n); break; }
                default: throw new NotSupportedException("kind");
            }
        }

        static string CatchOrder(int kind)
        {
            try
            {
                Raise(kind);
                return "none";
            }
            catch (ArgumentNullException) { return "ArgNull"; }
            catch (ArgumentOutOfRangeException) { return "ArgRange"; }
            catch (ArgumentException) { return "Arg"; }
            catch (RangeValidationException r) { return "Range" + r.Code; }
            catch (ValidationException v) { return "Valid" + v.Code; }
            catch (SystemException s) { return "Sys:" + Kind(s); }
            catch (Exception) { return "Other"; }
        }

        static void DisposeOrder(bool fail)
        {
            var log = new List<string>();
            try
            {
                using (new Tracker("outer", log))
                using (var mid = new Tracker("mid", log))
                {
                    log.Add("body");
                    using (new Tracker("inner", log))
                    {
                        if (fail) throw new ValidationException("dispose", 3);
                        log.Add("inner-body");
                    }
                    log.Add("after-inner");
                }
            }
            catch (ValidationException v)
            {
                log.Add("caught " + v.Code);
            }
            Out("dispose fail=" + fail + ": " + string.Join(", ", log));
        }

        static int ParseDigitStrict(char c)
        {
            if (c < '0' || c > '9') throw new FormatException("not a digit: " + c);
            return c - '0';
        }

        static void LoopAndSwitch()
        {
            string input = "12a4-7z90";
            int sum = 0, errors = 0, minus = 0;
            for (int i = 0; i < input.Length; i++)
            {
                try
                {
                    switch (input[i])
                    {
                        case '-':
                            minus++;
                            throw new ValidationException("minus", 100 + i);
                        case 'z':
                            throw new InvalidOperationException("z");
                        default:
                            sum = sum * 3 + ParseDigitStrict(input[i]);
                            break;
                    }
                }
                catch (FormatException fe)
                {
                    errors++;
                    Out("  pos " + i + " format: " + fe.Message);
                }
                catch (ValidationException v) when (v.Code > 100)
                {
                    errors += 10;
                    Out("  pos " + i + " " + Describe(v));
                }
                catch (InvalidOperationException)
                {
                    errors += 100;
                    Out("  pos " + i + " invalid op");
                }
            }
            Out("loop sum=" + sum + " errors=" + errors + " minus=" + minus);
        }

        static void CheckedArithmetic()
        {
            int[] values = { 1, 1000, 46340, 46341, int.MaxValue };
            foreach (int v in values)
            {
                try
                {
                    int sq = checked(v * v);
                    Out("square " + v + " = " + sq);
                }
                catch (OverflowException)
                {
                    Out("square " + v + " overflow, unchecked=" + unchecked(v * v));
                }
            }
            long big = 300;
            try
            {
                byte b = checked((byte)big);
                Out("byte " + b);
            }
            catch (OverflowException)
            {
                Out("byte overflow, unchecked=" + unchecked((byte)big));
            }
            int zero = values.Length - 5;
            try
            {
                Out("div " + (10 / zero));
            }
            catch (DivideByZeroException)
            {
                Out("divide by zero caught");
            }
        }

        static void Aggregates()
        {
            var agg = new AggregateException("top",
                new ValidationException("a", 1),
                new AggregateException("nested",
                    new ValidationException("b", 2),
                    new AggregateException(new ValidationException("c", 3), new InvalidOperationException("io"))),
                new ValidationException("d", 4));
            Out("aggregate direct=" + agg.InnerExceptions.Count);
            var flat = agg.Flatten();
            Out("aggregate flat=" + flat.InnerExceptions.Count);
            int codeSum = 0;
            foreach (var e in flat.InnerExceptions)
            {
                var v = e as ValidationException;
                Out("  flat: " + (v != null ? v.Field + "/" + v.Code : Kind(e)));
                if (v != null) codeSum = codeSum * 10 + v.Code;
            }
            Out("aggregate codes=" + codeSum);
            try
            {
                flat.Handle(e => e is ValidationException);
            }
            catch (AggregateException rest)
            {
                Out("unhandled remaining=" + rest.InnerExceptions.Count + " first=" + Kind(rest.InnerExceptions[0]));
            }
        }

        static int Main()
        {
            for (int mode = 0; mode < 3; mode++)
                Out("nested mode " + mode + ": " + NestedOrder(mode));
            int[] codes = { 501, 402, 403 };
            foreach (int c in codes)
                Out("filter " + c + ": " + FilterOrder(c));

            int total = 0;
            for (int x = 3; x <= 8; x++)
                total += ReturnThroughFinally(x);
            Out("return-finally total=" + total + " counter=" + finallyCounter);
            Out("loop-finally: " + LoopWithFinally());

            var trail = new List<string>();
            try
            {
                Descend(5, trail);
            }
            catch (PipelineException p)
            {
                Out("descend " + Describe(p));
            }
            Out("descend trail: " + string.Join(" ", trail));

            Rethrow(true);
            Rethrow(false);

            var order = new StringBuilder();
            for (int k = 0; k < 9; k++)
                order.Append(k).Append('=').Append(CatchOrder(k)).Append(' ');
            Out("catch order: " + order.ToString().TrimEnd());

            DisposeOrder(false);
            DisposeOrder(true);
            LoopAndSwitch();
            CheckedArithmetic();
            Aggregates();

            Console.WriteLine("checksum=" + checksum.ToString("X8", CultureInfo.InvariantCulture));
            return 0;
        }
    }
}
