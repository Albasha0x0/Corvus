using System.Runtime.InteropServices;
using Corvus.Core;

namespace Corvus.Native.Live;

/// <summary>One UI Automation element of a program's window tree: control view properties and its depth under the top-level window.</summary>
public sealed record UiElement(int Depth, string ControlType, string? Name, string? AutomationId, string? ClassName, string? Framework,
    ulong Window, int X, int Y, int Width, int Height, bool Enabled, bool Offscreen);

/// <summary>
/// Reads the UI Automation control view of a process's visible top-level windows (CUIAutomation8 through its COM
/// vtables; slots from the Windows SDK's UIAutomationClient.h). The program's UI threads answer each query, so a hung
/// program is bounded by the connection and transaction timeouts. Windows only.
/// </summary>
public static class UiAutomation
{
    public const int MaxElements = 2000, MaxDepth = 16;
    private const int ConnectionTimeoutMs = 2000, TransactionTimeoutMs = 5000;
    private static readonly Guid Clsid = new("e22ad333-b25f-460c-83d0-0581107395c9");
    private static readonly Guid Iid = new("34723aff-0c9d-49d0-9896-7ab52df8cd8a");

    /// <summary>The visible top-level windows of <paramref name="pid"/>, in z-order.</summary>
    public static List<IntPtr> TopLevelWindows(int pid)
    {
        var windows = new List<IntPtr>();
        EnumWindows((h, _) =>
        {
            if (GetWindowThreadProcessId(h, out var owner) != 0 && owner == pid && IsWindowVisible(h)) windows.Add(h);
            return true;
        }, IntPtr.Zero);
        return windows;
    }

    /// <summary>
    /// The control view under each of <paramref name="windows"/>, depth first, at most <see cref="MaxElements"/> elements
    /// and <see cref="MaxDepth"/> levels; <paramref name="truncated"/> says a limit was reached.
    /// </summary>
    public static List<UiElement> Read(IReadOnlyList<IntPtr> windows, CancellationToken ct, out bool truncated)
    {
        var rows = new List<UiElement>();
        bool cut = false;
        Exception? failure = null;
        // UI Automation clients run in the multithreaded apartment; a thread of its own keeps the caller's apartment as it is.
        var thread = new Thread(() =>
        {
            try { Walk(windows, rows, ct, ref cut); }
            catch (Exception e) { failure = e; }
        }) { IsBackground = true };
        if (OperatingSystem.IsWindows()) thread.SetApartmentState(ApartmentState.MTA);
        thread.Start();
        thread.Join();
        if (failure is OperationCanceledException) throw failure;
        if (failure != null) throw new ToolError(ErrorCode.Failed, "UI Automation could not read the windows: " + failure.Message);
        truncated = cut;
        return rows;
    }

    private static void Walk(IReadOnlyList<IntPtr> windows, List<UiElement> rows, CancellationToken ct, ref bool truncated)
    {
        var iid = Iid;
        var clsid = Clsid;
        Check(CoCreateInstance(ref clsid, IntPtr.Zero, 1, ref iid, out var automation), "CoCreateInstance(CUIAutomation8)");
        IntPtr walker = IntPtr.Zero;
        try
        {
            Call<SetU32Fn>(automation, 61)(automation, ConnectionTimeoutMs);
            Call<SetU32Fn>(automation, 63)(automation, TransactionTimeoutMs);
            Check(Call<GetPtrFn>(automation, 14)(automation, out walker), "ControlViewWalker");
            foreach (var window in windows)
            {
                ct.ThrowIfCancellationRequested();
                if (Call<FromHandleFn>(automation, 6)(automation, window, out var root) != 0 || root == IntPtr.Zero) continue;
                Visit(walker, root, 0, rows, ct, ref truncated);
            }
        }
        finally
        {
            Release(walker);
            Release(automation);
        }
    }

    // Takes ownership of element.
    private static void Visit(IntPtr walker, IntPtr element, int depth, List<UiElement> rows, CancellationToken ct, ref bool truncated)
    {
        try
        {
            if (rows.Count >= MaxElements) { truncated = true; return; }
            ct.ThrowIfCancellationRequested();
            rows.Add(Describe(element, depth));
            if (depth + 1 >= MaxDepth)
            {
                if (Call<ElementFn>(walker, 4)(walker, element, out var deeper) == 0 && deeper != IntPtr.Zero) { truncated = true; Release(deeper); }
                return;
            }
            if (Call<ElementFn>(walker, 4)(walker, element, out var child) != 0) return;
            while (child != IntPtr.Zero)
            {
                var next = IntPtr.Zero;
                if (Call<ElementFn>(walker, 6)(walker, child, out next) != 0) next = IntPtr.Zero;
                Visit(walker, child, depth + 1, rows, ct, ref truncated);
                child = next;
                if (rows.Count >= MaxElements && child != IntPtr.Zero) { truncated = true; Release(child); break; }
            }
        }
        finally { Release(element); }
    }

    private static UiElement Describe(IntPtr e, int depth)
    {
        int type = Call<GetI32Fn>(e, 21)(e, out var t) == 0 ? t : 0;
        Call<GetPtrFn>(e, 36)(e, out var hwnd);
        var rect = new Rect();
        Call<RectFn>(e, 43)(e, ref rect);
        bool enabled = Call<GetI32Fn>(e, 28)(e, out var en) == 0 && en != 0;
        bool offscreen = Call<GetI32Fn>(e, 38)(e, out var off) == 0 && off != 0;
        return new UiElement(depth, ControlTypeName(type), Text(e, 23), Text(e, 29), Text(e, 30), Text(e, 40), (ulong)hwnd,
            rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top, enabled, offscreen);
    }

    private static string? Text(IntPtr e, int slot)
    {
        if (Call<GetPtrFn>(e, slot)(e, out var bstr) != 0 || bstr == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringBSTR(bstr) is { Length: > 0 } s ? s : null; }
        finally { SysFreeString(bstr); }
    }

    /// <summary>The UIA programmatic name of a control type id (UIA_ButtonControlTypeId is 50000), or the number when it is not one.</summary>
    public static string ControlTypeName(int id) => id - 50000 is var i && i >= 0 && i < ControlTypes.Length ? ControlTypes[i] : id.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private static readonly string[] ControlTypes =
    [
        "Button", "Calendar", "CheckBox", "ComboBox", "Edit", "Hyperlink", "Image", "ListItem", "List", "Menu", "MenuBar", "MenuItem",
        "ProgressBar", "RadioButton", "ScrollBar", "Slider", "Spinner", "StatusBar", "Tab", "TabItem", "Text", "ToolBar", "ToolTip",
        "Tree", "TreeItem", "Custom", "Group", "Thumb", "DataGrid", "DataItem", "Document", "SplitButton", "Window", "Pane", "Header",
        "HeaderItem", "Table", "TitleBar", "Separator", "SemanticZoom", "AppBar",
    ];

    /// <summary>
    /// The class window procedure of <paramref name="hwnd"/> (GCLP_WNDPROC; another process cannot read a window's own
    /// procedure or dialog procedure), its control id and its parent when it is a child window; zeros when it has none.
    /// </summary>
    public static (ulong ClassProcedure, int ControlId, IntPtr Parent) WindowClass(IntPtr hwnd)
    {
        const int GclpWndProc = -24, GwlStyle = -16;
        const long WsChild = 0x40000000;
        var procedure = (ulong)GetClassLongPtrW(hwnd, GclpWndProc);
        bool child = (GetWindowLongPtrW(hwnd, GwlStyle) & WsChild) != 0;
        return (procedure, child ? GetDlgCtrlID(hwnd) : 0, child ? GetAncestor(hwnd, 1) : IntPtr.Zero);
    }

    /// <summary>
    /// A PNG of <paramref name="hwnd"/> as the program draws it (PrintWindow, PW_RENDERFULLCONTENT), with its width and
    /// height; null when the window has no area or did not draw.
    /// </summary>
    public static (byte[] Png, int Width, int Height)? Image(IntPtr hwnd)
    {
        if (!GetWindowRect(hwnd, out var r) || r.Right <= r.Left || r.Bottom <= r.Top) return null;
        int w = Math.Min(r.Right - r.Left, 8192), h = Math.Min(r.Bottom - r.Top, 8192);
        var screen = GetDC(IntPtr.Zero);
        var dc = CreateCompatibleDC(screen);
        // BITMAPINFOHEADER of a top-down 32-bit DIB: a negative height puts row 0 first.
        var header = new int[10];
        header[0] = 40; header[1] = w; header[2] = -h; header[3] = 1 | (32 << 16);
        var bitmap = CreateDIBSection(dc, header, 0, out var bits, IntPtr.Zero, 0);
        try
        {
            if (bitmap == IntPtr.Zero) return null;
            var old = SelectObject(dc, bitmap);
            bool drawn = PrintWindow(hwnd, dc, 2);
            SelectObject(dc, old);
            if (!drawn) return null;
            var pixels = new byte[w * h * 4];
            Marshal.Copy(bits, pixels, 0, pixels.Length);
            // BGRX to RGBA, opaque.
            for (int i = 0; i < pixels.Length; i += 4)
            {
                (pixels[i], pixels[i + 2]) = (pixels[i + 2], pixels[i]);
                pixels[i + 3] = 255;
            }
            return (PngWriter.Rgba(w, h, pixels), w, h);
        }
        finally
        {
            if (bitmap != IntPtr.Zero) DeleteObject(bitmap);
            DeleteDC(dc);
            _ = ReleaseDC(IntPtr.Zero, screen);
        }
    }

    private static void Check(int hr, string what)
    {
        if (hr < 0) throw new ToolError(ErrorCode.Failed, $"{what} failed (HRESULT 0x{hr:X8}).");
    }

    private static void Release(IntPtr p)
    {
        if (p != IntPtr.Zero) Call<ReleaseFn>(p, 2)(p);
    }

    private static T Call<T>(IntPtr self, int slot) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(self), slot * IntPtr.Size));

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate uint ReleaseFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int SetU32Fn(IntPtr self, uint value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int GetPtrFn(IntPtr self, out IntPtr value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int GetI32Fn(IntPtr self, out int value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int RectFn(IntPtr self, ref Rect value);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int FromHandleFn(IntPtr self, IntPtr hwnd, out IntPtr element);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int ElementFn(IntPtr self, IntPtr element, out IntPtr result);

    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("ole32.dll")] private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr result);
    [DllImport("oleaut32.dll")] private static extern void SysFreeString(IntPtr bstr);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetClassLongPtrW(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern long GetWindowLongPtrW(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateDIBSection(IntPtr dc, int[] header, uint usage, out IntPtr bits, IntPtr section, uint offset);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
}
