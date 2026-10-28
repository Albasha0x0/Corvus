using System.Text;

namespace Corvus.Native.Providers;

/// <summary>
/// Lines of <paramref name="inner"/> without their end ("\n" or "\r\n"); null
/// at the end of the text; a line longer than <paramref name="maxChars"/>
/// throws <see cref="InvalidDataException"/> before it is held whole.
/// </summary>
internal sealed class BoundedLineReader(TextReader inner, int maxChars)
{
    private readonly char[] _buffer = new char[8192];
    private int _at, _end;

    public string? ReadLine()
    {
        StringBuilder? partial = null;
        while (true)
        {
            if (_at == _end)
            {
                _at = 0;
                _end = Math.Max(0, inner.Read(_buffer, 0, _buffer.Length));
                if (_end == 0) return partial == null ? null : Trim(partial.ToString());
            }
            int newline = Array.IndexOf(_buffer, '\n', _at, _end - _at);
            int stop = newline < 0 ? _end : newline;
            if ((long)(partial?.Length ?? 0) + (stop - _at) > maxChars)
                throw new InvalidDataException($"a line passed {maxChars:N0} characters");
            if (newline >= 0 && partial == null)
            {
                var line = new string(_buffer, _at, stop - _at);
                _at = newline + 1;
                return Trim(line);
            }
            (partial ??= new StringBuilder()).Append(_buffer, _at, stop - _at);
            _at = stop;
            if (newline < 0) continue;
            _at = newline + 1;
            return Trim(partial.ToString());
        }
    }

    private static string Trim(string line) => line.EndsWith('\r') ? line[..^1] : line;
}
