using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

class WindowGuardCBT
{
    #region P/Invoke

    [DllImport("user32.dll")]
    static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint threadId);

    [DllImport("user32.dll")]
    static extern bool UnhookWindowsHookEx(IntPtr hook);

    [DllImport("user32.dll")]
    static extern IntPtr CallNextHookEx(IntPtr hook, int code, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string name);

    [DllImport("kernel32.dll")]
    static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll")]
    static extern bool WriteFile(IntPtr hFile, byte[] buf, uint len, out uint written, IntPtr ovl);

    [DllImport("user32.dll")]
    static extern IntPtr MonitorFromWindow(IntPtr h, uint dfl);

    [DllImport("user32.dll")]
    static extern bool GetMonitorInfo(IntPtr m, ref MONITORINFO mi);

    [DllImport("user32.dll")]
    static extern bool SetWindowPos(IntPtr h, IntPtr ins, int x, int y, int cx, int cy, uint f);

    [DllImport("user32.dll")]
    static extern bool GetWindowRect(IntPtr h, out RECT r);

    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr h);

    [DllImport("user32.dll")]
    static extern int GetWindowLong(IntPtr h, int idx);

    [DllImport("user32.dll")]
    static extern bool RedrawWindow(IntPtr h, IntPtr rect, IntPtr rgn, uint flags);

    [DllImport("user32.dll")]
    static extern bool EnumWindows(EnumWndProc proc, IntPtr lp);

    [DllImport("user32.dll")]
    static extern short GetAsyncKeyState(int vKey);

    [DllImport("user32.dll")]
    static extern bool GetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);

    [DllImport("user32.dll")]
    static extern bool SetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    static extern int GetClassName(IntPtr h, System.Text.StringBuilder sb, int max);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr sa, uint prot,
        uint sizeHigh, uint sizeLow, string name);

    [DllImport("kernel32.dll")]
    static extern IntPtr MapViewOfFile(IntPtr hMap, uint access, uint offHigh,
        uint offLow, UIntPtr bytes);

    delegate bool EnumWndProc(IntPtr h, IntPtr lp);

    // Делегат для хука — должен быть вызываемым из нашего процесса
    delegate IntPtr HookProc(int code, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X, Y; }

    [StructLayout(LayoutKind.Sequential)]
    struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINDOWPLACEMENT
    {
        public int   length;
        public int   flags;
        public int   showCmd;
        public POINT ptMinPosition;
        public POINT ptMaxPosition;
        public RECT  rcNormalPosition;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CBT_CREATEWND
    {
        public IntPtr lpcs;           // → CREATESTRUCT
        public IntPtr hwndInsertAfter;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    struct CREATESTRUCT
    {
        public IntPtr lpCreateParams;
        public IntPtr hInstance;
        public IntPtr hMenu;
        public IntPtr hwndParent;
        public int cy, cx, y, x;
        public int style;
        public IntPtr lpszName;
        public IntPtr lpszClass;
        public int dwExStyle;
    }

    const int WH_CBT            = 5;
    const int HCBT_CREATEWND    = 3;
    const int HCBT_MOVESIZE     = 0;
    const int HCBT_ACTIVATE     = 5;
    const int GWL_STYLE         = -16;
    const int GWL_EXSTYLE       = -20;
    const int WS_CAPTION        = 0x00C00000;
    const int WS_CHILD          = 0x40000000;
    const int WS_EX_TOOLWINDOW  = 0x00000080;
    const int WS_EX_APPWINDOW   = 0x00040000;
    const uint MONITOR_DEFAULTTOPRIMARY = 1;
    const uint MONITOR_DEFAULTTONEAREST = 2;
    const uint SWP_NOZORDER     = 0x0004;
    const uint SWP_NOACTIVATE   = 0x0010;
    const uint SWP_NOSENDCHANGING = 0x0400;
    const uint RDW_INVALIDATE   = 0x0001;
    const uint RDW_UPDATENOW    = 0x0100;
    const uint RDW_ALLCHILDREN  = 0x0080;

    #endregion

    // Shared memory для коммуникации хук-DLL → наш процесс
    const string SHARED_MEM_NAME = "WindowGuardCBT_SharedMem";
    const int SHARED_MEM_SIZE = 4096;

    static IntPtr _primary;
    static IntPtr _hookHandle;
    static IntPtr _hookDllHandle;
    static string _hookDllPath;

    // Храним делегат чтобы GC не собрал
    static HookProc _hookProcDelegate;

    static readonly Dictionary<IntPtr, IntPtr> _approved = new Dictionary<IntPtr, IntPtr>();
    static readonly HashSet<IntPtr> _dragging = new HashSet<IntPtr>();
    static bool _paused = false;

    [STAThread]
    static void Main()
    {
        bool createdNew;
        var mutex = new Mutex(true, "WindowGuardCBT_SingleInstance", out createdNew);
        if (!createdNew) return;

        Application.EnableVisualStyles();

        _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);

        // Создаём минимальную hook DLL
        _hookDllPath = CreateHookDll();
        if (_hookDllPath == null)
        {
            MessageBox.Show("Не удалось создать hook DLL", "WindowGuard CBT",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Загружаем DLL и ставим хук
        _hookDllHandle = LoadLibrary(_hookDllPath);
        if (_hookDllHandle == IntPtr.Zero)
        {
            MessageBox.Show("Не удалось загрузить hook DLL", "WindowGuard CBT",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        IntPtr procAddr = GetProcAddress(_hookDllHandle, "CBTProc");
        if (procAddr == IntPtr.Zero)
        {
            MessageBox.Show("Не найдена CBTProc в DLL", "WindowGuard CBT",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Глобальный CBT хук — инжектится во ВСЕ процессы
        _hookHandle = SetWindowsHookEx(WH_CBT, procAddr, _hookDllHandle, 0);

        if (_hookHandle == IntPtr.Zero)
        {
            MessageBox.Show("SetWindowsHookEx failed", "WindowGuard CBT",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Запоминаем текущие окна
        EnumWindows((h, lp) =>
        {
            if (IsRealWindow(h))
                _approved[h] = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
            return true;
        }, IntPtr.Zero);

        // Поллинг shared memory — DLL пишет туда hwnd новых окон
        var timer = new System.Windows.Forms.Timer { Interval = 50 };
        timer.Tick += (s, e) => PollSharedMemory();
        timer.Start();

        // Трей
        var menu = new ContextMenuStrip();
        menu.Items.Add("WindowGuard CBT — активен", null, null).Enabled = false;
        menu.Items.Add("-");
        menu.Items.Add("Выход", null, (s, e) =>
        {
            UnhookWindowsHookEx(_hookHandle);
            FreeLibrary(_hookDllHandle);
            try { File.Delete(_hookDllPath); } catch { }
            Application.Exit();
        });

        var tray = new NotifyIcon
        {
            Text    = "WindowGuard CBT",
            Icon    = SystemIcons.Shield,
            Visible = true,
            ContextMenuStrip = menu
        };

        Application.Run();
        tray.Visible = false;
        mutex.ReleaseMutex();
    }

    static bool IsRealWindow(IntPtr hwnd)
    {
        if (!IsWindowVisible(hwnd)) return false;
        int style = GetWindowLong(hwnd, GWL_STYLE);
        int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        if ((style & WS_CHILD) != 0) return false;
        if ((style & WS_CAPTION) == 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;
        if ((exStyle & WS_EX_TOOLWINDOW) != 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;
        return true;
    }

    static void PollSharedMemory()
    {
        // Читаем из shared memory список hwnd которые DLL перехватила
        // и проверяем/переносим их
        // (реализация зависит от формата данных в DLL)
    }

    /// <summary>
    /// Генерирует минимальную нативную DLL с CBT hook процедурой.
    /// DLL при HCBT_CREATEWND модифицирует координаты CREATESTRUCT
    /// чтобы окно создавалось на primary мониторе.
    /// </summary>
    static string CreateHookDll()
    {
        // Это x64 DLL. Для полной поддержки нужна и x86 версия.
        // Ниже — минимальный PE с одной экспортируемой функцией CBTProc.
        //
        // CBTProc:
        //   if (nCode == HCBT_CREATEWND) {
        //     CREATESTRUCT* cs = ((CBT_CREATEWND*)lParam)->lpcs;
        //     cs->x = primaryX;  // записываем координаты primary монитора
        //     cs->y = primaryY;
        //   }
        //   return CallNextHookEx(0, nCode, wParam, lParam);

        // Для реального использования нужен компилятор или заранее
        // скомпилированный бинарник. Вот подход с runtime-компиляцией:

        string src = @"
#include <windows.h>

#pragma comment(lib, ""user32.lib"")

static HHOOK g_hook = NULL;

// Координаты primary монитора — обновляются через shared memory
static RECT g_primaryWork = {0, 0, 1920, 1080};

BOOL CALLBACK MonitorEnumProc(HMONITOR hMon, HDC hdc, LPRECT rc, LPARAM lp) {
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfo(hMon, &mi);
    if (mi.dwFlags & MONITORINFOF_PRIMARY) {
        g_primaryWork = mi.rcWork;
        return FALSE;
    }
    return TRUE;
}

extern ""C"" __declspec(dllexport)
LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HCBT_CREATEWND) {
        CBT_CREATEWND* cw = (CBT_CREATEWND*)lParam;
        CREATESTRUCT* cs = (CREATESTRUCT*)cw->lpcs;

        // Только top-level окна с заголовком
        if (cs->hwndParent == NULL &&
            (cs->style & WS_CAPTION) &&
            !(cs->dwExStyle & WS_EX_TOOLWINDOW)) {

            EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0);

            int areaW = g_primaryWork.right  - g_primaryWork.left;
            int areaH = g_primaryWork.bottom - g_primaryWork.top;

            if (cs->x == CW_USEDEFAULT || cs->y == CW_USEDEFAULT) {
                cs->x = g_primaryWork.left + (areaW - cs->cx) / 2;
                cs->y = g_primaryWork.top  + (areaH - cs->cy) / 2;
            } else {
                // Проверяем — если координаты за пределами primary, переносим
                POINT pt = { cs->x + cs->cx/2, cs->y + cs->cy/2 };
                HMONITOR hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
                HMONITOR hPrimary = MonitorFromWindow(NULL, MONITOR_DEFAULTTOPRIMARY);
                if (hMon != hPrimary) {
                    cs->x = g_primaryWork.left + (areaW - cs->cx) / 2;
                    cs->y = g_primaryWork.top  + (areaH - cs->cy) / 2;
                }
            }
        }
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    return TRUE;
}
";

        // Сохраняем исходник и компилируем через cl.exe или встроенный компилятор
        string tempDir = Path.Combine(Path.GetTempPath(), "WindowGuard");
        Directory.CreateDirectory(tempDir);
        string srcPath = Path.Combine(tempDir, "hook.cpp");
        string dllPath = Path.Combine(tempDir, "wghook.dll");

        File.WriteAllText(srcPath, src);

        // Попробовать скомпилировать через встроенный cl.exe
        // Если нет Visual Studio — используем заранее скомпилированный бинарник
        // (см. ниже — embedded binary)

        return CompileWithCl(srcPath, dllPath) ? dllPath : CreateEmbeddedDll(dllPath);
    }

    static bool CompileWithCl(string srcPath, string dllPath)
    {
        // Ищем cl.exe в стандартных путях VS
        string[] searchPaths = {
            @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
            @"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
            @"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC"
        };

        // Упрощённо — в реальности нужен полный поиск
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "cl.exe",
                Arguments = $"/LD /O2 /Fe\"{dllPath}\" \"{srcPath}\" user32.lib",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            var proc = Process.Start(psi);
            proc.WaitForExit(10000);
            return proc.ExitCode == 0 && File.Exists(dllPath);
        }
        catch
        {
            return false;
        }
    }

    static string CreateEmbeddedDll(string dllPath)
    {
        // Заранее скомпилированная минимальная DLL (x64)
        // В реальном проекте — включить как embedded resource
        // Здесь placeholder
        return null;
    }
}