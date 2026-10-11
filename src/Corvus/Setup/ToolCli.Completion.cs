using System.Text;

namespace Corvus.Setup;

/// <summary>Shell completion scripts generated from the command words, tool names and each tool's parameter names.</summary>
internal static partial class ToolCli
{
    public static readonly string[] Shells = ["bash", "zsh", "pwsh"];

    /// <summary>Options offered after a tool name.</summary>
    private static readonly string[] CallOptions = ["--load", "--json", "--structured", "--args", "--args-file", "--max-output", "--timeout", "--toolsets"];

    private static int Completion(CliArgs a, CliIo io)
    {
        if (a.Positionals is not [var shell] || !Shells.Contains(shell.ToLowerInvariant()))
            throw new UsageException($"completion takes one shell: {string.Join(", ", Shells)}.");
        io.Out.Write(CompletionScript(shell.ToLowerInvariant()));
        return Exit.Ok;
    }

    public static string CompletionScript(string shell)
    {
        var words = SetupCli.Words.Concat(Commands).Distinct().ToList();
        var tools = CatalogTools.Select(NameOf).Order(StringComparer.Ordinal).ToList();
        var parameters = CatalogTools.ToDictionary(NameOf, t => Parameters(t).Select(p => p.Name + "=").ToList());
        var sb = new StringBuilder();
        if (shell == "pwsh")
        {
            sb.Append($"# {Program} completion for PowerShell. Load: {Program} completion pwsh | Out-String | Invoke-Expression\n");
            sb.Append("Register-ArgumentCompleter -Native -CommandName corvus, corvus.exe -ScriptBlock {\n");
            sb.Append("    param($wordToComplete, $commandAst, $cursorPosition)\n");
            sb.Append($"    $commands = @({Quoted(words, "'")})\n");
            sb.Append($"    $tools = @({Quoted(tools, "'")})\n");
            sb.Append($"    $options = @({Quoted(CallOptions, "'")})\n");
            sb.Append("    $params = @{\n");
            foreach (var tool in tools) sb.Append($"        '{tool}' = @({Quoted(parameters[tool], "'")})\n");
            sb.Append("    }\n");
            sb.Append("""
                    $words = @($commandAst.CommandElements | ForEach-Object { "$_" })
                    $before = if ($wordToComplete) { $words.Count - 1 } else { $words.Count }
                    $candidates = @()
                    if ($before -le 1) { $candidates = $commands + $tools }
                    else {
                        $tool = $words[1]
                        if ($tool -in 'call', 'describe', 'help') {
                            if ($before -eq 2) { $candidates = $tools } else { $tool = $words[2] }
                        }
                        if (-not $candidates) { $candidates = @($params[$tool.Replace('-', '_')]) + $options }
                    }
                    $candidates | Where-Object { $_ -and $_ -like "$wordToComplete*" } | ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                    }
                }

                """);
            return sb.ToString();
        }
        sb.Append($"# {Program} completion for {shell}. Load: source <({Program} completion {shell})\n");
        if (shell == "zsh") sb.Append("autoload -U +X bashcompinit && bashcompinit\n");
        sb.Append("_corvus() {\n");
        sb.Append("    local cur=\"${COMP_WORDS[COMP_CWORD]}\" prev=\"${COMP_WORDS[COMP_CWORD-1]}\" tool=\"${COMP_WORDS[1]}\" params=\"\"\n");
        sb.Append($"    local commands=\"{string.Join(' ', words)}\"\n");
        sb.Append($"    local tools=\"{string.Join(' ', tools)}\"\n");
        sb.Append("""
                if [ "$COMP_CWORD" -eq 1 ]; then COMPREPLY=($(compgen -W "$commands $tools" -- "$cur")); return; fi
                # A value after name= completes as a file path.
                if [ "$prev" = "=" ] || [[ "$cur" == *=* ]]; then COMPREPLY=($(compgen -f -- "${cur#*=}")); return; fi
                case "$tool" in
                    call|describe|help)
                        if [ "$COMP_CWORD" -eq 2 ]; then COMPREPLY=($(compgen -W "$tools" -- "$cur")); return; fi
                        tool="${COMP_WORDS[2]}" ;;
                esac
                case "${tool//-/_}" in

            """);
        foreach (var tool in tools) sb.Append($"        {tool}) params=\"{string.Join(' ', parameters[tool])}\" ;;\n");
        sb.Append("    esac\n");
        sb.Append($"    COMPREPLY=($(compgen -W \"$params {string.Join(' ', CallOptions)}\" -- \"$cur\"))\n");
        sb.Append("    [[ \"${COMPREPLY[0]}\" == *= ]] && compopt -o nospace 2>/dev/null\n");
        sb.Append("}\n");
        sb.Append("complete -F _corvus corvus\n");
        return sb.ToString();
    }

    private static string Quoted(IEnumerable<string> items, string quote) => string.Join(", ", items.Select(i => quote + i + quote));
}
