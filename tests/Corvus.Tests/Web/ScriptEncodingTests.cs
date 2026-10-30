using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Corvus.Services.Web.Scripts;

namespace Corvus.Tests;

/// <summary>Script Encoder text decoded before the language reader runs.</summary>
public sealed class ScriptEncodingTests
{
    // Encoder written from the documented algorithm: each character below 128
    // steps the position, which picks one of three substitutions.
    internal static string Encode(string source)
    {
        var body = new StringBuilder();
        int index = -1;
        foreach (char c in source)
        {
            if (c >= 128) { body.Append(c); continue; }
            index++;
            switch (c)
            {
                case '\n': body.Append("@&"); continue;
                case '\r': body.Append("@#"); continue;
                case '>': body.Append("@*"); continue;
                case '<': body.Append("@!"); continue;
                case '@': body.Append("@$"); continue;
            }
            if (c != '\t' && c < ' ') { body.Append(c); continue; }
            int pick = ScriptEncoding.Pick[index % 64];
            body.Append((char)ScriptEncoding.Table.First(e => e.Value[pick] == c).Key);
        }
        return "#@~^AAAAAA==" + body + "BBBBBB==^#~@";
    }

    private const string Source = "Set s = CreateObject(\"WScript.Shell\")\r\nIf a < b And c > d Then x = \"me@host\"\r\nt = Chr(72) & Chr(105)\r\ns.Run \"cmd /c echo corvus marker\"\r\n";

    private static ScriptFileView.Facts? View(string name, string text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        return new ScriptFileView().Inspect(new FileInput(name, data, Blob.Identify(data)), default)?.Detail as ScriptFileView.Facts;
    }

    [Fact]
    public void Text_encoded_by_the_documented_algorithm_decodes_to_the_source()
    {
        Assert.Equal(Source, ScriptEncoding.Decode(Encode(Source), out int blocks));
        Assert.Equal(1, blocks);
    }

    // The worked example in the Script Encoder decoder manual, independent of the test's encoder.
    [Fact]
    public void A_published_encoded_line_decodes_to_its_published_source()
    {
        Assert.Equal("MsgBox \"Hello\"", ScriptEncoding.Decode(@"#@~^DgAAAA==\ko$K6,JC" + "\u007F" + @"V^GJqAQAAA==^#~@", out int blocks));
        Assert.Equal(1, blocks);
    }

    [Fact]
    public void An_encoded_vbe_file_is_read_as_vbscript_with_its_strings_folded()
    {
        var facts = View("a.vbe", Encode(Source))!;
        Assert.Equal("vbscript", facts.Language);
        Assert.Contains("corvus marker", facts.Plain);
        Assert.Contains("\"Hi\"", facts.Plain);
        Assert.Contains(facts.Notes!, n => n.Contains("Script Encoder"));
    }

    [Fact]
    public void An_encoded_jse_file_is_read_as_javascript()
    {
        var facts = View("a.jse", Encode("var m = 'corvus ' + 'marker'; if (a < b) { new ActiveXObject('WScript.Shell').Run(m); }"))!;
        Assert.Equal("javascript", facts.Language);
        Assert.Contains("corvus marker", facts.Plain);
    }

    [Fact]
    public void An_encoded_block_in_an_application_page_is_read_in_its_language()
    {
        var facts = View("a.hta", "<html><script language=\"VBScript.Encode\">" + Encode(Source) + "</script></html>")!;
        Assert.Contains("corvus marker", facts.Plain);
        Assert.Contains("\"Hi\"", facts.Plain);
    }

    [Fact]
    public void Text_that_only_resembles_a_block_is_left_unchanged()
    {
        const string text = "x = \"#@~^ not an encoded block\"\r\n";
        Assert.Equal(text, ScriptEncoding.Decode(text, out int blocks));
        Assert.Equal(0, blocks);
        Assert.DoesNotContain(View("a.vbs", text)?.Notes ?? [], n => n.Contains("Script Encoder"));
    }
}
