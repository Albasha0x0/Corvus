using System.Buffers.Binary;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>inspect_process view=windows on a window program this test builds: the UI Automation tree, class procedures and the window image.</summary>
[Trait("Speed", "Slow")]
public sealed class LiveWindowsTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    // A main window of class SampleWindow (procedure MainProc) with an OK button (id 101) and an edit box (id 102).
    private const string App = """
        #include <windows.h>
        #include <stdio.h>

        static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l)
        {
            if (m == WM_COMMAND && LOWORD(w) == 101) { SetWindowTextW(GetDlgItem(h, 102), L"clicked"); return 0; }
            if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
            return DefWindowProcW(h, m, w, l);
        }

        int main(void)
        {
            WNDCLASSW c = { 0 };
            c.lpfnWndProc = MainProc; c.hInstance = GetModuleHandleW(NULL); c.lpszClassName = L"SampleWindow";
            c.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); c.hCursor = LoadCursor(NULL, IDC_ARROW);
            RegisterClassW(&c);
            HWND main = CreateWindowW(L"SampleWindow", L"Sample settings", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 360, 200, NULL, NULL, c.hInstance, NULL);
            CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 20, 20, 100, 30, main, (HMENU)101, c.hInstance, NULL);
            CreateWindowW(L"EDIT", L"ready", WS_CHILD | WS_VISIBLE | WS_BORDER, 20, 70, 200, 24, main, (HMENU)102, c.hInstance, NULL);
            printf("%d ready\n", GetCurrentProcessId()); fflush(stdout);
            MSG msg;
            while (GetMessageW(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
            return 0;
        }
        """;

    // Prints type id|name|automation id|class name for each control view element under the visible top-level windows of a process.
    private const string Tree = """
        #define COBJMACROS
        #include <windows.h>
        #include <uiautomationclient.h>
        #include <stdio.h>

        static IUIAutomation* uia;
        static IUIAutomationTreeWalker* walker;
        static DWORD pid;

        static void Text(BSTR s) { printf("%ls", s ? s : L""); SysFreeString(s); }

        static void Visit(IUIAutomationElement* e)
        {
            CONTROLTYPEID type = 0; BSTR name = NULL, id = NULL, cls = NULL;
            IUIAutomationElement_get_CurrentControlType(e, &type);
            IUIAutomationElement_get_CurrentName(e, &name);
            IUIAutomationElement_get_CurrentAutomationId(e, &id);
            IUIAutomationElement_get_CurrentClassName(e, &cls);
            printf("%d|", type); Text(name); printf("|"); Text(id); printf("|"); Text(cls); printf("\n");
            IUIAutomationElement* child = NULL;
            IUIAutomationTreeWalker_GetFirstChildElement(walker, e, &child);
            while (child) {
                IUIAutomationElement* next = NULL;
                IUIAutomationTreeWalker_GetNextSiblingElement(walker, child, &next);
                Visit(child);
                IUIAutomationElement_Release(child);
                child = next;
            }
        }

        static BOOL CALLBACK Top(HWND h, LPARAM l)
        {
            DWORD owner = 0; GetWindowThreadProcessId(h, &owner);
            if (owner == pid && IsWindowVisible(h)) {
                IUIAutomationElement* e = NULL;
                if (SUCCEEDED(IUIAutomation_ElementFromHandle(uia, h, &e)) && e) { Visit(e); IUIAutomationElement_Release(e); }
            }
            return TRUE;
        }

        int main(int argc, char** argv)
        {
            pid = (DWORD)atoi(argv[1]);
            CoInitializeEx(NULL, COINIT_MULTITHREADED);
            if (FAILED(CoCreateInstance(&CLSID_CUIAutomation8, NULL, CLSCTX_INPROC_SERVER, &IID_IUIAutomation, (void**)&uia))) return 1;
            IUIAutomation_get_ControlViewWalker(uia, &walker);
            EnumWindows(Top, 0);
            return 0;
        }
        """;

    public void Dispose() => _dir.Dispose();

    /// <summary>
    /// The elements equal what a C program walking the same control view with the SDK's UI Automation headers lists;
    /// the window's class procedure is MainProc by its PDB name, the button's notifications
    /// go to MainProc, and the image has the window's size.
    /// </summary>
    [Fact]
    public async Task A_window_programs_elements_and_handlers_are_listed_as_ui_automation_reads_them()
    {
        if (!OperatingSystem.IsWindows() || VisualStudio.VcVarsAll() is not { } vcvars) return;
        File.WriteAllText(_dir.File("ui.c"), App);
        File.WriteAllText(_dir.File("tree.c"), Tree);
        var (code, log) = Tools.Run(new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = _dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" x64 >nul && cl /nologo /Zi ui.c user32.lib /link /DEBUG /INCREMENTAL:NO && cl /nologo tree.c user32.lib ole32.lib oleaut32.lib uiautomationcore.lib\"",
        }, 300_000);
        Assert.True(code == 0 && File.Exists(_dir.File("ui.exe")) && File.Exists(_dir.File("tree.exe")), log);
        using var program = Process.Start(new ProcessStartInfo(_dir.File("ui.exe")) { RedirectStandardOutput = true, UseShellExecute = false })!;
        try
        {
            using (var wait = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
                await program.StandardOutput.ReadLineAsync(wait.Token);
            using var dumps = new MinidumpService();
            var service = new LiveProcessService(dumps);
            var image = _dir.File("window.png");
            var r = await service.Inspect(program.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), "windows", null, 0, 1000, null, 1, null, 60, default, image);
            var rows = r.Items!.Cast<LiveProcessService.UiRow>().ToList();
            foreach (var row in rows) output.WriteLine(Corvus.Tools.DumpText.UiElement(row));

            var main = rows.Single(e => e.ClassName == "SampleWindow");
            Assert.Equal("Window", main.ControlType);
            Assert.Equal("Sample settings", main.Name);
            Assert.Equal("ui!MainProc", main.ClassProcedureSymbol);
            var ok = rows.Single(e => e.Name == "OK");
            Assert.Equal(("Button", 101, "ui!MainProc"), (ok.ControlType, ok.ControlId, ok.Notifies));
            Assert.Equal(102, rows.Single(e => e.ClassName == "Edit").ControlId);

            var reference = Reference(program.Id);
            Assert.Equal(reference.Order(StringComparer.Ordinal), rows.Select(e => $"{e.ControlType}|{e.Name}|{e.AutomationId}|{e.ClassName}").Order(StringComparer.Ordinal));

            var png = File.ReadAllBytes(image);
            var (w, h) = (BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16)), BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20)));
            Assert.Equal(main.Bounds.Split(' ')[1], $"{w}x{h}");
            Assert.True(r.Detached);
        }
        finally { program.Kill(); }
    }

    // The control view of the process's visible top-level windows, walked by Tree (native UI Automation, C).
    private string[] Reference(int pid)
    {
        var (code, text) = Tools.Run(new ProcessStartInfo(_dir.File("tree.exe"), pid.ToString(System.Globalization.CultureInfo.InvariantCulture)), 120_000);
        Assert.True(code == 0, text);
        return [.. text.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Split('|') is var f ? $"{Corvus.Native.Live.UiAutomation.ControlTypeName(int.Parse(f[0], System.Globalization.CultureInfo.InvariantCulture))}|{f[1]}|{f[2]}|{f[3]}" : l)];
    }
}
