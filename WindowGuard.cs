using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

class WindowGuard
{
    #region P/Invoke

    delegate void WinEventProc(IntPtr hook, uint evType, IntPtr hwnd,
        int idObject, int idChild, uint thread, uint time);
    delegate bool EnumWndProc(IntPtr h, IntPtr lp);

    [DllImport("user32.dll")]
    static extern IntPtr SetWinEventHook(uint eMin, uint eMax, IntPtr hMod,
        WinEventProc proc, uint pid, uint tid, uint flags);
    [DllImport("user32.dll")] static extern bool UnhookWinEvent(IntPtr hook);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] static extern int  GetWindowLong(IntPtr h, int i);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr ins,
        int x, int y, int cx, int cy, uint f);
    [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr h, uint dfl);
    [DllImport("user32.dll")] static extern IntPtr MonitorFromPoint(POINT pt, uint dfl);
    [DllImport("user32.dll")] static extern bool GetMonitorInfo(IntPtr m, ref MONITORINFO mi);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWndProc proc, IntPtr lp);
    [DllImport("user32.dll")] static extern bool RedrawWindow(IntPtr h, IntPtr rect, IntPtr rgn, uint flags);
    [DllImport("user32.dll")] static extern bool GetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);
    [DllImport("user32.dll")] static extern bool SetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);
    [DllImport("user32.dll")] static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] static extern bool GetCursorPos(out POINT pt);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    static extern int GetClassName(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint threadId);
    [DllImport("user32.dll")] static extern bool UnhookWindowsHookEx(IntPtr hook);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string name);
    [DllImport("kernel32.dll")]
    static extern bool FreeLibrary(IntPtr hModule);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    // Shared memory
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpAttr,
        uint flProtect, uint dwMaxHigh, uint dwMaxLow, string lpName);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr MapViewOfFile(IntPtr hMap, uint dwAccess,
        uint dwOffHigh, uint dwOffLow, UIntPtr dwBytes);
    [DllImport("kernel32.dll")]
    static extern bool UnmapViewOfFile(IntPtr lpBase);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)]
    struct WINDOWPLACEMENT
    {
        public int length, flags, showCmd;
        public POINT ptMinPosition, ptMaxPosition;
        public RECT rcNormalPosition;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor, rcWork;
        public uint dwFlags;
    }

    const uint EVENT_OBJECT_SHOW           = 0x8002;
    const uint EVENT_OBJECT_LOCATIONCHANGE = 0x800B;
    const uint EVENT_SYSTEM_MOVESIZESTART  = 0x000A;
    const uint EVENT_SYSTEM_MOVESIZEEND    = 0x000B;
    const uint EVENT_SYSTEM_FOREGROUND     = 0x0003;
    const int  VK_SHIFT = 0x10, VK_LWIN = 0x5B, VK_RWIN = 0x5C;
    const int  SW_SHOWNOACTIVATE = 4;
    const uint WINEVENT_OUTOFCONTEXT = 0, WINEVENT_SKIPOWNPROCESS = 2;
    const int  GWL_STYLE = -16, GWL_EXSTYLE = -20;
    const int  WS_CAPTION = 0x00C00000, WS_CHILD = 0x40000000;
    const int  WS_EX_TOOLWINDOW = 0x00000080, WS_EX_NOACTIVATE = 0x08000000;
    const int  WS_EX_APPWINDOW = 0x00040000;
    const uint MONITOR_DEFAULTTOPRIMARY = 1, MONITOR_DEFAULTTONEAREST = 2;
    const uint SWP_NOSIZE = 0x0001, SWP_NOZORDER = 0x0004, SWP_NOACTIVATE = 0x0010;
    const uint SWP_NOSENDCHANGING = 0x0400, SWP_ASYNCWINDOWPOS = 0x4000;
    const uint RDW_INVALIDATE = 0x0001, RDW_UPDATENOW = 0x0100, RDW_ALLCHILDREN = 0x0080;
    const int  WH_CBT = 5;
    const uint PAGE_READWRITE = 0x04;
    const uint FILE_MAP_WRITE = 0x0002;

    #endregion

    // ─── Shared memory layout (должен совпадать с C-структурой в DLL) ───
    // Offset  0: interceptCount (int32, volatile)
    // Offset  4: primaryLeft    (int32)
    // Offset  8: primaryTop     (int32)
    // Offset 12: primaryRight   (int32)
    // Offset 16: primaryBottom  (int32)
    // Offset 20: enabled        (int32)
    const string CBT_SHARED_NAME = "Local\\WindowGuardCBT";
    const int CBT_SHARED_SIZE = 4096;
    const int OFF_COUNT   = 0;
    const int OFF_LEFT    = 4;
    const int OFF_TOP     = 8;
    const int OFF_RIGHT   = 12;
    const int OFF_BOTTOM  = 16;
    const int OFF_ENABLED = 20;

    enum EngineMode { Original, Improved, CBTHook }

    static EngineMode _mode = EngineMode.Improved;
    static IntPtr _primary;
    static bool _paused = false;
    static DateTime _displayChangedAt = DateTime.MinValue;
    const int DISPLAY_SETTLE_MS = 4000;

    static readonly Dictionary<IntPtr, IntPtr> _approved = new Dictionary<IntPtr, IntPtr>();
    static readonly HashSet<IntPtr> _dragging = new HashSet<IntPtr>();

    // Original
    static readonly Dictionary<IntPtr, DateTime> _pendingNew = new Dictionary<IntPtr, DateTime>();
    static readonly Dictionary<IntPtr, DateTime> _wgMovedOrig = new Dictionary<IntPtr, DateTime>();
    const int NEW_WINDOW_DELAY_MS = 300;
    const int WG_MOVED_GRACE_MS_ORIG = 1500;

    // Improved
    static readonly Dictionary<IntPtr, int> _recheck = new Dictionary<IntPtr, int>();
    static readonly Dictionary<IntPtr, DateTime> _wgMovedImpr = new Dictionary<IntPtr, DateTime>();
    const int RECHECK_ATTEMPTS = 3;
    const int WG_MOVED_GRACE_MS_IMPR = 1500;

    // CBT Hook
    static IntPtr _cbtHookHandle;
    static IntPtr _cbtDllHandle;
    static string _cbtDllPath;
    static IntPtr _sharedMapHandle;
    static IntPtr _sharedMemPtr;

    // WinEvent хуки
    static readonly List<WinEventProc> _delegates = new List<WinEventProc>();
    static readonly List<IntPtr> _hookHandles = new List<IntPtr>();

    static readonly HashSet<string> _ignoreClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "tooltips_class32", "Shell_TrayWnd", "DV2ControlHost",
        "Shell_SecondaryTrayWnd", "Progman", "WorkerW",
        "NotifyIconOverflowWindow", "Windows.UI.Core.CoreWindow", "#32768"
    };

    static NotifyIcon _tray;
    static ToolStripMenuItem _itemOriginal, _itemImproved, _itemCBT, _itemPause;
    static System.Windows.Forms.Timer _timer;

    // ═══════════════════════════════════════════════════════════════
    //  MAIN
    // ═══════════════════════════════════════════════════════════════

    [STAThread]
    static void Main()
    {
        bool createdNew;
        var mutex = new Mutex(true, "WindowGuard_AllInOne", out createdNew);
        if (!createdNew)
        {
            MessageBox.Show("WindowGuard уже запущен.", "WindowGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Application.EnableVisualStyles();
        SyncAutostartPath();
        _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);

        SystemEvents.DisplaySettingsChanged += delegate
        {
            _displayChangedAt = DateTime.UtcNow;
            _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
            UpdateSharedPrimaryCoords();
        };
        SystemEvents.PowerModeChanged += delegate(object s, PowerModeChangedEventArgs e)
        {
            if (e.Mode == PowerModes.Resume)
            {
                _displayChangedAt = DateTime.UtcNow;
                _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
                UpdateSharedPrimaryCoords();
            }
        };

        SnapshotExistingWindows();

        _timer = new System.Windows.Forms.Timer();
        _timer.Interval = 100;
        _timer.Tick += delegate { TimerTick(); };
        _timer.Start();

        BuildTray();
        SwitchEngine(EngineMode.Improved);
        Application.Run();

        StopCurrentEngine();
        _tray.Visible = false;
        mutex.ReleaseMutex();
    }

    // ═══════════════════════════════════════════════════════════════
    //  ПЕРЕКЛЮЧЕНИЕ ДВИЖКОВ
    // ═══════════════════════════════════════════════════════════════

    static void SwitchEngine(EngineMode newMode)
    {
        StopCurrentEngine();
        _mode = newMode;
        _pendingNew.Clear();
        _wgMovedOrig.Clear();
        _recheck.Clear();
        _wgMovedImpr.Clear();
        SnapshotExistingWindows();

        switch (newMode)
        {
            case EngineMode.Original: StartOriginalEngine(); break;
            case EngineMode.Improved: StartImprovedEngine(); break;
            case EngineMode.CBTHook:  StartCBTEngine();      break;
        }
        UpdateTrayChecks();
    }

    static void StopCurrentEngine()
    {
        // Снять WinEvent хуки
        foreach (IntPtr h in _hookHandles) UnhookWinEvent(h);
        _hookHandles.Clear();
        _delegates.Clear();

        // Снять CBT хук
        if (_cbtHookHandle != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_cbtHookHandle);
            _cbtHookHandle = IntPtr.Zero;
        }
        if (_cbtDllHandle != IntPtr.Zero)
        {
            FreeLibrary(_cbtDllHandle);
            _cbtDllHandle = IntPtr.Zero;
        }

        // Уничтожить shared memory (сначала отключаем — DLL перестанет перехватывать)
        DestroySharedMemory();

        // DLL-файл не удаляем — он может быть ещё загружен в чужих процессах
    }

    static void SnapshotExistingWindows()
    {
        _approved.Clear();
        _dragging.Clear();
        EnumWindows(delegate(IntPtr h, IntPtr lp)
        {
            if (IsReal(h))
                _approved[h] = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
            return true;
        }, IntPtr.Zero);
    }

    // ═══════════════════════════════════════════════════════════════
    //  SHARED MEMORY (для CBT DLL)
    // ═══════════════════════════════════════════════════════════════

    static bool CreateSharedMemory()
    {
        _sharedMapHandle = CreateFileMapping(
            new IntPtr(-1),   // INVALID_HANDLE_VALUE — файл в pagefile
            IntPtr.Zero,      // default security
            PAGE_READWRITE,
            0,
            (uint)CBT_SHARED_SIZE,
            CBT_SHARED_NAME);

        if (_sharedMapHandle == IntPtr.Zero) return false;

        _sharedMemPtr = MapViewOfFile(
            _sharedMapHandle,
            FILE_MAP_WRITE,   // read + write
            0, 0,
            UIntPtr.Zero);    // map всё

        if (_sharedMemPtr == IntPtr.Zero)
        {
            CloseHandle(_sharedMapHandle);
            _sharedMapHandle = IntPtr.Zero;
            return false;
        }

        // Обнулить всю область
        for (int i = 0; i < 24; i += 4)
            Marshal.WriteInt32(_sharedMemPtr, i, 0);

        // Записать координаты primary монитора
        UpdateSharedPrimaryCoords();

        // Включить перехват
        Marshal.WriteInt32(_sharedMemPtr, OFF_ENABLED, 1);
        return true;
    }

    static void UpdateSharedPrimaryCoords()
    {
        if (_sharedMemPtr == IntPtr.Zero) return;
        MONITORINFO mi = new MONITORINFO();
        mi.cbSize = Marshal.SizeOf(typeof(MONITORINFO));
        if (GetMonitorInfo(_primary, ref mi))
        {
            Marshal.WriteInt32(_sharedMemPtr, OFF_LEFT,   mi.rcWork.Left);
            Marshal.WriteInt32(_sharedMemPtr, OFF_TOP,    mi.rcWork.Top);
            Marshal.WriteInt32(_sharedMemPtr, OFF_RIGHT,  mi.rcWork.Right);
            Marshal.WriteInt32(_sharedMemPtr, OFF_BOTTOM, mi.rcWork.Bottom);
        }
    }

    static int ReadInterceptCount()
    {
        if (_sharedMemPtr == IntPtr.Zero) return 0;
        return Marshal.ReadInt32(_sharedMemPtr, OFF_COUNT);
    }

    static void DestroySharedMemory()
    {
        if (_sharedMemPtr != IntPtr.Zero)
        {
            // Отключить перехват — DLL в чужих процессах сразу перестанет работать
            Marshal.WriteInt32(_sharedMemPtr, OFF_ENABLED, 0);
            UnmapViewOfFile(_sharedMemPtr);
            _sharedMemPtr = IntPtr.Zero;
        }
        if (_sharedMapHandle != IntPtr.Zero)
        {
            CloseHandle(_sharedMapHandle);
            _sharedMapHandle = IntPtr.Zero;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  ДВИЖОК 1: ORIGINAL
    // ═══════════════════════════════════════════════════════════════

    static void StartOriginalEngine()
    {
        HookEvent(EVENT_OBJECT_SHOW,           EVENT_OBJECT_SHOW,           Orig_OnShow);
        HookEvent(EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE, Orig_OnLocationChange);
        HookEvent(EVENT_SYSTEM_MOVESIZESTART,  EVENT_SYSTEM_MOVESIZESTART,  Orig_OnDragStart);
        HookEvent(EVENT_SYSTEM_MOVESIZEEND,    EVENT_SYSTEM_MOVESIZEEND,    Orig_OnDragEnd);
    }

    static void Orig_OnShow(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused || obj != 0 || child != 0) return;
        if (!IsRealOriginal(hwnd)) return;
        _approved[hwnd] = _primary;
        if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
            _pendingNew[hwnd] = DateTime.UtcNow;
    }

    static void Orig_OnLocationChange(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused || obj != 0 || child != 0) return;
        if (!_approved.ContainsKey(hwnd) || _dragging.Contains(hwnd)) return;
        if (_pendingNew.ContainsKey(hwnd) || !IsRealOriginal(hwnd)) return;
        IntPtr newMon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (newMon == _approved[hwnd]) return;
        if (IsWinShiftHeld()) _approved[hwnd] = newMon;
    }

    static void Orig_OnDragStart(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time) { _dragging.Add(hwnd); }

    static void Orig_OnDragEnd(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    { _dragging.Remove(hwnd); _approved[hwnd] = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST); }

    static void Orig_TimerTick()
    {
        DateTime now = DateTime.UtcNow;
        if (CheckDisplaySettle(now)) return;

        List<IntPtr> ready = new List<IntPtr>();
        foreach (KeyValuePair<IntPtr, DateTime> kv in _pendingNew)
            if ((now - kv.Value).TotalMilliseconds >= NEW_WINDOW_DELAY_MS) ready.Add(kv.Key);
        foreach (IntPtr h in ready)
        {
            _pendingNew.Remove(h);
            if (IsWindow(h) && IsRealOriginal(h) && MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) != _primary)
                PutOn(h, _primary, true);
        }

        List<IntPtr> dead = new List<IntPtr>();
        foreach (KeyValuePair<IntPtr, IntPtr> kv in new Dictionary<IntPtr, IntPtr>(_approved))
        {
            IntPtr hwnd = kv.Key;
            if (!IsWindowVisible(hwnd))
            {
                DateTime movedAt;
                if (_wgMovedOrig.TryGetValue(hwnd, out movedAt) &&
                    (now - movedAt).TotalMilliseconds < WG_MOVED_GRACE_MS_ORIG)
                { ShowWindow(hwnd, SW_SHOWNOACTIVATE); continue; }
                dead.Add(hwnd); continue;
            }
            if (_dragging.Contains(hwnd) || _pendingNew.ContainsKey(hwnd) || IsIconic(hwnd)) continue;
            if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != kv.Value)
                PutOn(hwnd, kv.Value, false);
        }
        foreach (IntPtr h in dead)
        { _approved.Remove(h); _dragging.Remove(h); _pendingNew.Remove(h); _wgMovedOrig.Remove(h); }
        CleanExpired(_wgMovedOrig, WG_MOVED_GRACE_MS_ORIG, now);
    }

    static bool IsRealOriginal(IntPtr hwnd)
    {
        if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) return false;
        if ((GetWindowLong(hwnd, GWL_STYLE) & WS_CAPTION) == 0) return false;
        if ((GetWindowLong(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) != 0) return false;
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    //  ДВИЖОК 2: IMPROVED
    // ═══════════════════════════════════════════════════════════════

    static void StartImprovedEngine()
    {
        HookEvent(EVENT_OBJECT_SHOW,           EVENT_OBJECT_SHOW,           Impr_OnShow);
        HookEvent(EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE, Impr_OnLocationChange);
        HookEvent(EVENT_SYSTEM_MOVESIZESTART,  EVENT_SYSTEM_MOVESIZESTART,  Impr_OnDragStart);
        HookEvent(EVENT_SYSTEM_MOVESIZEEND,    EVENT_SYSTEM_MOVESIZEEND,    Impr_OnDragEnd);
        HookEvent(EVENT_SYSTEM_FOREGROUND,     EVENT_SYSTEM_FOREGROUND,     Impr_OnForeground);
    }

    static void Impr_OnShow(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused || obj != 0 || child != 0) return;
        if (!IsReal(hwnd) || _approved.ContainsKey(hwnd)) return;
        _approved[hwnd] = _primary;
        if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
        { PutOn(hwnd, _primary, true); _recheck[hwnd] = RECHECK_ATTEMPTS; }
    }

    static void Impr_OnForeground(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused || hwnd == IntPtr.Zero) return;
        if (_approved.ContainsKey(hwnd) || !IsReal(hwnd)) return;
        _approved[hwnd] = _primary;
        if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
        { PutOn(hwnd, _primary, true); _recheck[hwnd] = RECHECK_ATTEMPTS; }
    }

    static void Impr_OnLocationChange(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused || obj != 0 || child != 0) return;
        if (!_approved.ContainsKey(hwnd) || _dragging.Contains(hwnd)) return;
        if (!IsReal(hwnd)) return;
        IntPtr newMon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (newMon == _approved[hwnd]) return;
        if (IsWinShiftHeld()) { _approved[hwnd] = newMon; return; }
        PutOn(hwnd, _approved[hwnd], false);
    }

    static void Impr_OnDragStart(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time) { _dragging.Add(hwnd); }

    static void Impr_OnDragEnd(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        _dragging.Remove(hwnd);
        if (IsWindow(hwnd)) _approved[hwnd] = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    }

    static void Impr_TimerTick()
    {
        DateTime now = DateTime.UtcNow;
        if (CheckDisplaySettle(now)) return;

        List<IntPtr> recheckDone = new List<IntPtr>();
        foreach (KeyValuePair<IntPtr, int> kv in new Dictionary<IntPtr, int>(_recheck))
        {
            IntPtr hwnd = kv.Key;
            if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) { recheckDone.Add(hwnd); continue; }
            if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
            {
                PutOn(hwnd, _primary, false);
                int left = kv.Value - 1;
                if (left <= 0) recheckDone.Add(hwnd); else _recheck[hwnd] = left;
            }
            else recheckDone.Add(hwnd);
        }
        foreach (IntPtr h in recheckDone) _recheck.Remove(h);

        List<IntPtr> dead = new List<IntPtr>();
        foreach (KeyValuePair<IntPtr, IntPtr> kv in new Dictionary<IntPtr, IntPtr>(_approved))
        {
            IntPtr hwnd = kv.Key;
            if (!IsWindow(hwnd)) { dead.Add(hwnd); continue; }
            if (!IsWindowVisible(hwnd))
            {
                DateTime movedAt;
                if (_wgMovedImpr.TryGetValue(hwnd, out movedAt) &&
                    (now - movedAt).TotalMilliseconds < WG_MOVED_GRACE_MS_IMPR)
                { ShowWindow(hwnd, SW_SHOWNOACTIVATE); continue; }
                dead.Add(hwnd); continue;
            }
            if (_dragging.Contains(hwnd) || _recheck.ContainsKey(hwnd) || IsIconic(hwnd)) continue;
            if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != kv.Value)
                PutOn(hwnd, kv.Value, false);
        }
        foreach (IntPtr h in dead)
        { _approved.Remove(h); _dragging.Remove(h); _recheck.Remove(h); _wgMovedImpr.Remove(h); }
        CleanExpired(_wgMovedImpr, WG_MOVED_GRACE_MS_IMPR, now);
    }

    // ═══════════════════════════════════════════════════════════════
    //  ДВИЖОК 3: CBT HOOK (глобальный хук через DLL + shared memory)
    // ═══════════════════════════════════════════════════════════════
    //
    //  Как работает:
    //  1. Наш процесс создаёт shared memory "Local\WindowGuardCBT"
    //     и записывает туда координаты рабочей области primary монитора
    //  2. Наш процесс компилирует wghook64.dll (или wghook32.dll)
    //     с функцией CBTProc и загружает через LoadLibrary
    //  3. SetWindowsHookEx(WH_CBT, CBTProc, hDll, 0) — глобальный хук
    //     Windows АВТОМАТИЧЕСКИ инжектит DLL в каждый процесс
    //     при создании окна (ленивая загрузка)
    //  4. CBTProc в DLL (внутри чужого процесса):
    //     - Открывает shared memory через OpenFileMapping
    //     - Читает координаты primary монитора
    //     - При HCBT_CREATEWND модифицирует CREATESTRUCT.x/.y
    //     - Инкрементирует счётчик перехваченных окон
    //  5. Наш процесс читает счётчик через shared memory
    //     и показывает в tray tooltip

    static void StartCBTEngine()
    {
        // WinEvent хуки для drag/location/foreground — дополнение к CBT
        HookEvent(EVENT_OBJECT_SHOW,           EVENT_OBJECT_SHOW,           Impr_OnShow);
        HookEvent(EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE, Impr_OnLocationChange);
        HookEvent(EVENT_SYSTEM_MOVESIZESTART,  EVENT_SYSTEM_MOVESIZESTART,  Impr_OnDragStart);
        HookEvent(EVENT_SYSTEM_MOVESIZEEND,    EVENT_SYSTEM_MOVESIZEEND,    Impr_OnDragEnd);
        HookEvent(EVENT_SYSTEM_FOREGROUND,     EVENT_SYSTEM_FOREGROUND,     Impr_OnForeground);

        // 1. Создаём shared memory
        if (!CreateSharedMemory())
        {
            MessageBox.Show(
                "Не удалось создать shared memory.\nОшибка: " + Marshal.GetLastWin32Error() +
                "\nПереключаюсь на Improved.",
                "WindowGuard — CBT Hook", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            SwitchEngine(EngineMode.Improved);
            return;
        }

        // 2. Компилируем / находим DLL
        _cbtDllPath = BuildCBTHookDll();
        if (_cbtDllPath == null)
        {
            DestroySharedMemory();
            MessageBox.Show(
                "Не удалось создать CBT hook DLL.\n\n" +
                "Не найден C-компилятор. Проверены:\n" +
                "  - Visual Studio 2017/2019/2022 (cl.exe через vswhere)\n" +
                "  - gcc / mingw в PATH\n" +
                "  - tcc в PATH\n\n" +
                "Переключаюсь на Improved.",
                "WindowGuard — CBT Hook", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            SwitchEngine(EngineMode.Improved);
            return;
        }

        // 3. Загружаем DLL
        _cbtDllHandle = LoadLibrary(_cbtDllPath);
        if (_cbtDllHandle == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            DestroySharedMemory();
            MessageBox.Show(
                "LoadLibrary не удался (ошибка " + err + ").\n" + _cbtDllPath +
                "\nПереключаюсь на Improved.",
                "WindowGuard — CBT Hook", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            SwitchEngine(EngineMode.Improved);
            return;
        }

        // 4. Находим CBTProc
        IntPtr procAddr = GetProcAddress(_cbtDllHandle, "CBTProc");
        if (procAddr == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            FreeLibrary(_cbtDllHandle); _cbtDllHandle = IntPtr.Zero;
            DestroySharedMemory();
            MessageBox.Show(
                "CBTProc не найдена в DLL (ошибка " + err + ").\nПереключаюсь на Improved.",
                "WindowGuard — CBT Hook", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            SwitchEngine(EngineMode.Improved);
            return;
        }

        // 5. Ставим глобальный CBT хук
        //    threadId=0 → все потоки → Windows инжектит DLL во все GUI-процессы
        _cbtHookHandle = SetWindowsHookEx(WH_CBT, procAddr, _cbtDllHandle, 0);
        if (_cbtHookHandle == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            FreeLibrary(_cbtDllHandle); _cbtDllHandle = IntPtr.Zero;
            DestroySharedMemory();
            MessageBox.Show(
                "SetWindowsHookEx не удался (ошибка " + err + ").\nПереключаюсь на Improved.",
                "WindowGuard — CBT Hook", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            SwitchEngine(EngineMode.Improved);
            return;
        }

        // Успех!
    }

    static void CBT_TimerTick()
    {
        // Обновляем координаты primary (если сменился монитор)
        UpdateSharedPrimaryCoords();

        // Обновляем tooltip со счётчиком
        int count = ReadInterceptCount();
        if (_tray != null)
            _tray.Text = "WindowGuard [CBT] — перехвачено: " + count;

        // Для перемещения уже существующих окон — логика Improved
        Impr_TimerTick();
    }

    // ═══════════════════════════════════════════════════════════════
    //  ПОИСК КОМПИЛЯТОРА И СБОРКА CBT DLL
    // ═══════════════════════════════════════════════════════════════

    static string FindVcvarsall()
    {
        string programX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        // 1) vswhere.exe
        string vswhere = Path.Combine(programX86, @"Microsoft Visual Studio\Installer\vswhere.exe");
        if (!File.Exists(vswhere))
            vswhere = Path.Combine(programFiles, @"Microsoft Visual Studio\Installer\vswhere.exe");

        if (File.Exists(vswhere))
        {
            // С фильтром по C++ компоненту
            string path = RunVswhere(vswhere,
                "-latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath");
            if (path != null) return path;

            // Без фильтра — любая VS
            path = RunVswhere(vswhere, "-latest -products * -property installationPath");
            if (path != null) return path;
        }

        // 2) Ручной перебор
        string[] roots = new string[] { programFiles, programX86 };
        string[] years = new string[] { "2022", "2019", "2017" };
        string[] editions = new string[] { "Community", "Professional", "Enterprise", "BuildTools", "Preview" };

        foreach (string root in roots)
            foreach (string year in years)
                foreach (string edition in editions)
                {
                    string vcvars = Path.Combine(root,
                        "Microsoft Visual Studio", year, edition,
                        @"VC\Auxiliary\Build\vcvarsall.bat");
                    if (File.Exists(vcvars)) return vcvars;
                }

        // 3) Переменные окружения VS*COMNTOOLS
        string[] envVars = new string[] { "VS170COMNTOOLS", "VS160COMNTOOLS", "VS150COMNTOOLS", "VS140COMNTOOLS" };
        foreach (string envVar in envVars)
        {
            string val = Environment.GetEnvironmentVariable(envVar);
            if (string.IsNullOrEmpty(val)) continue;
            string vcvars = Path.GetFullPath(Path.Combine(val, @"..\..\VC\Auxiliary\Build\vcvarsall.bat"));
            if (File.Exists(vcvars)) return vcvars;
            vcvars = Path.GetFullPath(Path.Combine(val, @"..\..\VC\vcvarsall.bat"));
            if (File.Exists(vcvars)) return vcvars;
        }

        return null;
    }

    static string RunVswhere(string vswherePath, string args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = vswherePath;
            psi.Arguments = args;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            Process p = Process.Start(psi);
            string output = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(10000);
            if (!string.IsNullOrEmpty(output))
            {
                string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    string vcvars = Path.Combine(line.Trim(), @"VC\Auxiliary\Build\vcvarsall.bat");
                    if (File.Exists(vcvars)) return vcvars;
                }
            }
        }
        catch { }
        return null;
    }

    static string BuildCBTHookDll()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "WindowGuard");
        Directory.CreateDirectory(tempDir);

        bool is64 = IntPtr.Size == 8;
        string srcPath = Path.Combine(tempDir, "wghook.c");
        string dllPath = Path.Combine(tempDir, is64 ? "wghook64.dll" : "wghook32.dll");

        if (File.Exists(dllPath)) return dllPath;

        // C-исходник DLL с shared memory
        // DLL инжектится Windows во все GUI-процессы автоматически
        // При HCBT_CREATEWND читает координаты primary из shared memory
        // и модифицирует CREATESTRUCT чтобы окно создалось на primary
        string src =
            "#include <windows.h>\r\n" +
            "\r\n" +
            "#pragma comment(lib, \"user32.lib\")\r\n" +
            "\r\n" +
            "/* Shared memory layout — должен совпадать с C# кодом */\r\n" +
            "typedef struct {\r\n" +
            "    volatile LONG interceptCount;\r\n" +
            "    LONG primaryLeft;\r\n" +
            "    LONG primaryTop;\r\n" +
            "    LONG primaryRight;\r\n" +
            "    LONG primaryBottom;\r\n" +
            "    LONG enabled;\r\n" +
            "} WG_SHARED;\r\n" +
            "\r\n" +
            "#define WG_SHARED_NAME \"Local\\\\WindowGuardCBT\"\r\n" +
            "\r\n" +
            "static HANDLE  g_map    = NULL;\r\n" +
            "static WG_SHARED *g_shared = NULL;\r\n" +
            "\r\n" +
            "/* Лениво открываем shared memory (создан C# процессом) */\r\n" +
            "static void EnsureShared(void) {\r\n" +
            "    if (g_shared) return;\r\n" +
            "    g_map = OpenFileMappingA(FILE_MAP_WRITE, FALSE, WG_SHARED_NAME);\r\n" +
            "    if (!g_map) return;\r\n" +
            "    g_shared = (WG_SHARED*)MapViewOfFile(g_map, FILE_MAP_WRITE, 0, 0, 0);\r\n" +
            "    if (!g_shared) { CloseHandle(g_map); g_map = NULL; }\r\n" +
            "}\r\n" +
            "\r\n" +
            "/* Глобальная CBT hook процедура — вызывается в контексте ЧУЖОГО процесса */\r\n" +
            "__declspec(dllexport)\r\n" +
            "LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {\r\n" +
            "    if (nCode == HCBT_CREATEWND) {\r\n" +
            "        EnsureShared();\r\n" +
            "        if (g_shared && g_shared->enabled) {\r\n" +
            "            CBT_CREATEWND *cw = (CBT_CREATEWND*)lParam;\r\n" +
            "            CREATESTRUCT  *cs = (CREATESTRUCT*)cw->lpcs;\r\n" +
            "\r\n" +
            "            /* Только top-level окна с заголовком, не tool window */\r\n" +
            "            if (cs->hwndParent == NULL &&\r\n" +
            "                (cs->style & WS_CAPTION) == WS_CAPTION &&\r\n" +
            "                !(cs->dwExStyle & WS_EX_TOOLWINDOW)) {\r\n" +
            "\r\n" +
            "                int areaW = g_shared->primaryRight - g_shared->primaryLeft;\r\n" +
            "                int areaH = g_shared->primaryBottom - g_shared->primaryTop;\r\n" +
            "\r\n" +
            "                if (areaW > 0 && areaH > 0) {\r\n" +
            "                    int w = cs->cx > 0 ? cs->cx : areaW / 2;\r\n" +
            "                    int h = cs->cy > 0 ? cs->cy : areaH / 2;\r\n" +
            "                    int needMove = 0;\r\n" +
            "\r\n" +
            "                    /* CW_USEDEFAULT — координаты не заданы */\r\n" +
            "                    if (cs->x == (int)0x80000000 || cs->y == (int)0x80000000) {\r\n" +
            "                        needMove = 1;\r\n" +
            "                    } else {\r\n" +
            "                        /* Центр окна за пределами primary? */\r\n" +
            "                        int cx = cs->x + w / 2;\r\n" +
            "                        int cy = cs->y + h / 2;\r\n" +
            "                        if (cx < g_shared->primaryLeft  || cx >= g_shared->primaryRight ||\r\n" +
            "                            cy < g_shared->primaryTop   || cy >= g_shared->primaryBottom)\r\n" +
            "                            needMove = 1;\r\n" +
            "                    }\r\n" +
            "\r\n" +
            "                    if (needMove) {\r\n" +
            "                        cs->x = g_shared->primaryLeft + (areaW - w) / 2;\r\n" +
            "                        cs->y = g_shared->primaryTop  + (areaH - h) / 2;\r\n" +
            "                        InterlockedIncrement(&g_shared->interceptCount);\r\n" +
            "                    }\r\n" +
            "                }\r\n" +
            "            }\r\n" +
            "        }\r\n" +
            "    }\r\n" +
            "    return CallNextHookEx(NULL, nCode, wParam, lParam);\r\n" +
            "}\r\n" +
            "\r\n" +
            "BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {\r\n" +
            "    if (reason == DLL_PROCESS_ATTACH)\r\n" +
            "        DisableThreadLibraryCalls(hModule);\r\n" +
            "    if (reason == DLL_PROCESS_DETACH) {\r\n" +
            "        if (g_shared) { UnmapViewOfFile(g_shared); g_shared = NULL; }\r\n" +
            "        if (g_map)    { CloseHandle(g_map);        g_map    = NULL; }\r\n" +
            "    }\r\n" +
            "    return TRUE;\r\n" +
            "}\r\n";

        File.WriteAllText(srcPath, src);

        if (TryCompile_VS(srcPath, dllPath)) return dllPath;
        if (TryCompile_GCC(srcPath, dllPath, is64)) return dllPath;
        if (TryCompile_TCC(srcPath, dllPath)) return dllPath;

        return null;
    }

    static bool TryCompile_VS(string src, string dll)
    {
        // Сначала cl.exe напрямую (Developer Command Prompt)
        if (TryRunCL(src, dll)) return true;

        // Ищем vcvarsall.bat
        string vcvarsall = FindVcvarsall();
        if (vcvarsall == null) return false;

        string dir = Path.GetDirectoryName(dll);
        string batPath = Path.Combine(dir, "_wg_compile.bat");
        string arch = IntPtr.Size == 8 ? "x64" : "x86";

        string batContent =
            "@echo off\r\n" +
            "call \"" + vcvarsall + "\" " + arch + " >nul 2>&1\r\n" +
            "if errorlevel 1 exit /b 1\r\n" +
            "cd /d \"" + dir + "\"\r\n" +
            "cl.exe /nologo /LD /O2 /Fe\"" + dll + "\" \"" + src + "\" user32.lib /link /DLL >nul 2>&1\r\n" +
            "exit /b %errorlevel%\r\n";

        File.WriteAllText(batPath, batContent);
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c \"" + batPath + "\"";
            psi.WorkingDirectory = dir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(30000);
            CleanCompilerJunk(dir);
            return p.ExitCode == 0 && File.Exists(dll);
        }
        catch { return false; }
        finally { try { File.Delete(batPath); } catch { } }
    }

    static bool TryRunCL(string src, string dll)
    {
        try
        {
            string dir = Path.GetDirectoryName(dll);
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "cl.exe";
            psi.Arguments = "/nologo /LD /O2 /Fe\"" + dll + "\" \"" + src + "\" user32.lib /link /DLL";
            psi.WorkingDirectory = dir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            CleanCompilerJunk(dir);
            return p.ExitCode == 0 && File.Exists(dll);
        }
        catch { return false; }
    }

    static bool TryCompile_GCC(string src, string dll, bool x64)
    {
        string gcc = x64 ? "x86_64-w64-mingw32-gcc" : "i686-w64-mingw32-gcc";
        foreach (string compiler in new string[] { gcc, "gcc" })
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = compiler;
                psi.Arguments = "-shared -O2 -o \"" + dll + "\" \"" + src + "\" -luser32";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                Process p = Process.Start(psi);
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit(15000);
                if (p.ExitCode == 0 && File.Exists(dll)) return true;
            }
            catch { }
        }
        return false;
    }

    static bool TryCompile_TCC(string src, string dll)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "tcc";
            psi.Arguments = "-shared -o \"" + dll + "\" \"" + src + "\" -luser32";
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            Process p = Process.Start(psi);
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return p.ExitCode == 0 && File.Exists(dll);
        }
        catch { return false; }
    }

    static void CleanCompilerJunk(string dir)
    {
        foreach (string pat in new string[] { "*.obj", "*.lib", "*.exp", "*.ilk", "*.pdb" })
            try { foreach (string f in Directory.GetFiles(dir, pat)) try { File.Delete(f); } catch { } } catch { }
    }

    // ═══════════════════════════════════════════════════════════════
    //  ОБЩИЕ УТИЛИТЫ
    // ═══════════════════════════════════════════════════════════════

    static void HookEvent(uint eMin, uint eMax, WinEventProc proc)
    {
        _delegates.Add(proc);
        IntPtr h = SetWinEventHook(eMin, eMax, IntPtr.Zero, proc, 0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
        if (h != IntPtr.Zero) _hookHandles.Add(h);
    }

    static string GetClass(IntPtr hwnd)
    {
        StringBuilder sb = new StringBuilder(256);
        GetClassName(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    static bool IsReal(IntPtr hwnd)
    {
        if (!IsWindow(hwnd) || !IsWindowVisible(hwnd) || IsIconic(hwnd)) return false;
        int style = GetWindowLong(hwnd, GWL_STYLE);
        int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        if ((style & WS_CHILD) != 0) return false;
        if ((style & WS_CAPTION) == 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;
        if ((exStyle & WS_EX_TOOLWINDOW) != 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;
        if ((exStyle & WS_EX_NOACTIVATE) != 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;
        return !_ignoreClasses.Contains(GetClass(hwnd));
    }

    static bool IsWinShiftHeld()
    {
        bool win = (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0 || (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0;
        return win && (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    }

    static bool CheckDisplaySettle(DateTime now)
    {
        if (_displayChangedAt != DateTime.MinValue)
        {
            if ((now - _displayChangedAt).TotalMilliseconds >= DISPLAY_SETTLE_MS)
            { _displayChangedAt = DateTime.MinValue; MoveAllToPrimary(); }
            return true;
        }
        return false;
    }

    static void MoveAllToPrimary()
    {
        _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
        UpdateSharedPrimaryCoords();
        foreach (IntPtr h in new List<IntPtr>(_approved.Keys))
        {
            _approved[h] = _primary;
            if (IsReal(h) && MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) != _primary)
                PutOn(h, _primary, true);
        }
    }

    static void PutOn(IntPtr hwnd, IntPtr monitor, bool updatePlacement)
    {
        MONITORINFO mi = new MONITORINFO();
        mi.cbSize = Marshal.SizeOf(typeof(MONITORINFO));
        if (!GetMonitorInfo(monitor, ref mi)) return;

        RECT r; GetWindowRect(hwnd, out r);
        int w = r.Right - r.Left, h = r.Bottom - r.Top;
        int areaW = mi.rcWork.Right - mi.rcWork.Left;
        int areaH = mi.rcWork.Bottom - mi.rcWork.Top;
        if (w > areaW) w = areaW;
        if (h > areaH) h = areaH;
        int x = mi.rcWork.Left + Math.Max(0, (areaW - w) / 2);
        int y = mi.rcWork.Top  + Math.Max(0, (areaH - h) / 2);

        if (updatePlacement)
        {
            WINDOWPLACEMENT wp = new WINDOWPLACEMENT();
            wp.length = Marshal.SizeOf(typeof(WINDOWPLACEMENT));
            if (GetWindowPlacement(hwnd, ref wp))
            {
                wp.rcNormalPosition = new RECT { Left = x, Top = y, Right = x + w, Bottom = y + h };
                SetWindowPlacement(hwnd, ref wp);
            }
        }

        if (!IsIconic(hwnd))
        {
            if (_mode == EngineMode.Original) _wgMovedOrig[hwnd] = DateTime.UtcNow;
            else _wgMovedImpr[hwnd] = DateTime.UtcNow;

            SetWindowPos(hwnd, IntPtr.Zero, x, y, w, h,
                SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING | SWP_ASYNCWINDOWPOS);
            RedrawWindow(hwnd, IntPtr.Zero, IntPtr.Zero,
                RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
    }

    static void TimerTick()
    {
        if (_paused) return;
        switch (_mode)
        {
            case EngineMode.Original: Orig_TimerTick(); break;
            case EngineMode.Improved: Impr_TimerTick(); break;
            case EngineMode.CBTHook:  CBT_TimerTick();  break;
        }
    }

    static void CleanExpired(Dictionary<IntPtr, DateTime> dict, int graceMs, DateTime now)
    {
        List<IntPtr> expired = new List<IntPtr>();
        foreach (KeyValuePair<IntPtr, DateTime> kv in dict)
            if ((now - kv.Value).TotalMilliseconds >= graceMs) expired.Add(kv.Key);
        foreach (IntPtr h in expired) dict.Remove(h);
    }

    // ═══════════════════════════════════════════════════════════════
    //  ТРЕЙ
    // ═══════════════════════════════════════════════════════════════

    static void BuildTray()
    {
        ContextMenuStrip menu = new ContextMenuStrip();

        ToolStripMenuItem header = new ToolStripMenuItem("WindowGuard");
        header.Enabled = false;
        menu.Items.Add(header);
        menu.Items.Add(new ToolStripSeparator());

        ToolStripMenuItem modeLabel = new ToolStripMenuItem("Режим работы:");
        modeLabel.Enabled = false;
        menu.Items.Add(modeLabel);

        _itemOriginal = new ToolStripMenuItem("Original (задержка 300мс)");
        _itemOriginal.Click += delegate { SwitchEngine(EngineMode.Original); };
        menu.Items.Add(_itemOriginal);

        _itemImproved = new ToolStripMenuItem("Improved (мгновенный)");
        _itemImproved.Click += delegate { SwitchEngine(EngineMode.Improved); };
        menu.Items.Add(_itemImproved);

        _itemCBT = new ToolStripMenuItem("CBT Hook (глобальный хук в каждый процесс)");
        _itemCBT.Click += delegate { SwitchEngine(EngineMode.CBTHook); };
        menu.Items.Add(_itemCBT);

        menu.Items.Add(new ToolStripSeparator());

        ToolStripMenuItem autoStartItem = new ToolStripMenuItem("Автозапуск с Windows");
        autoStartItem.Checked = IsAutostart();
        autoStartItem.Click += delegate
        { SetAutostart(!autoStartItem.Checked); autoStartItem.Checked = IsAutostart(); };
        menu.Items.Add(autoStartItem);

        menu.Items.Add("Перенести все на основной монитор", null, delegate { MoveAllToPrimary(); });

        _itemPause = new ToolStripMenuItem("Пауза");
        _itemPause.CheckOnClick = true;
        _itemPause.CheckedChanged += delegate { _paused = _itemPause.Checked; };
        menu.Items.Add(_itemPause);

        menu.Items.Add("Перезапустить проводник", null, delegate
        {
            foreach (Process p in Process.GetProcessesByName("explorer")) p.Kill();
            Process.Start("explorer.exe");
        });

        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Выход", null, delegate { StopCurrentEngine(); Application.Exit(); });

        _tray = new NotifyIcon();
        _tray.Text = "WindowGuard";
        _tray.Icon = SystemIcons.Shield;
        _tray.Visible = true;
        _tray.ContextMenuStrip = menu;

        _tray.DoubleClick += delegate
        {
            string modeName;
            string extra = "";
            switch (_mode)
            {
                case EngineMode.Original: modeName = "Original"; break;
                case EngineMode.CBTHook:
                    modeName = "CBT Hook";
                    extra = "\nDLL: " + (_cbtDllPath ?? "(нет)") +
                            "\nShared memory: " + (_sharedMemPtr != IntPtr.Zero ? "OK" : "нет") +
                            "\nХук: " + (_cbtHookHandle != IntPtr.Zero ? "активен" : "нет") +
                            "\nПерехвачено окон: " + ReadInterceptCount() +
                            "\n\nDLL инжектится Windows автоматически" +
                            "\nво все " + (IntPtr.Size == 8 ? "64" : "32") + "-битные GUI-процессы.";
                    break;
                default: modeName = "Improved"; break;
            }
            MessageBox.Show(
                "WindowGuard работает.\n\n" +
                "Текущий режим: " + modeName + "\n" + extra + "\n\n" +
                "Original — перенос с задержкой 300мс\n" +
                "Improved — мгновенный перенос + повторные проверки\n" +
                "CBT Hook — глобальный хук, перехват CreateWindowEx\n\n" +
                "Отслеживается окон: " + _approved.Count,
                "WindowGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
        };

        UpdateTrayChecks();
    }

    static void UpdateTrayChecks()
    {
        if (_itemOriginal == null) return;
        _itemOriginal.Checked = (_mode == EngineMode.Original);
        _itemImproved.Checked = (_mode == EngineMode.Improved);
        _itemCBT.Checked      = (_mode == EngineMode.CBTHook);

        if (_mode != EngineMode.CBTHook && _tray != null)
        {
            string modeName;
            switch (_mode)
            {
                case EngineMode.Original: modeName = "Original"; break;
                default: modeName = "Improved"; break;
            }
            _tray.Text = "WindowGuard [" + modeName + "]";
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  АВТОЗАПУСК
    // ═══════════════════════════════════════════════════════════════

    const string RUN_KEY = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string APP_NAME = "WindowGuard";

    static bool IsAutostart()
    {
        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RUN_KEY, false))
            return key != null && key.GetValue(APP_NAME) != null;
    }

    static void SetAutostart(bool enable)
    {
        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RUN_KEY, true))
        {
            if (key == null) return;
            if (enable) key.SetValue(APP_NAME, Application.ExecutablePath);
            else key.DeleteValue(APP_NAME, false);
        }
    }

    static void SyncAutostartPath()
    {
        using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RUN_KEY, true))
        {
            if (key == null) return;
            string stored = key.GetValue(APP_NAME) as string;
            if (stored != null && stored != Application.ExecutablePath)
                key.SetValue(APP_NAME, Application.ExecutablePath);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  КАК РАБОТАЕТ CBT HOOK — СХЕМА ИНЖЕКЦИИ
// ═══════════════════════════════════════════════════════════════════
//
//  WindowGuard.exe (наш процесс)
//    │
//    ├─ CreateFileMapping("Local\WindowGuardCBT")
//    │   → Shared memory с координатами primary монитора
//    │
//    ├─ LoadLibrary("wghook64.dll")
//    │   → DLL загружена В НАШ процесс
//    │
//    ├─ SetWindowsHookEx(WH_CBT, CBTProc, hDll, 0)
//    │   → Windows РЕГИСТРИРУЕТ глобальный хук
//    │
//    │   ┌──── При создании окна в ЛЮБОМ 64-бит процессе: ────┐
//    │   │                                                      │
//    │   │  notepad.exe / chrome.exe / telegram.exe / ...       │
//    │   │    │                                                  │
//    │   │    ├─ CreateWindowEx(CW_USEDEFAULT, ...)             │
//    │   │    │   │                                              │
//    │   │    │   ├─ Windows видит: есть CBT hook!              │
//    │   │    │   │                                              │
//    │   │    │   ├─ Windows инжектит wghook64.dll              │
//    │   │    │   │   в адресное пространство этого процесса    │
//    │   │    │   │                                              │
//    │   │    │   ├─ Windows вызывает CBTProc(HCBT_CREATEWND)   │
//    │   │    │   │   внутри целевого процесса                  │
//    │   │    │   │                                              │
//    │   │    │   ├─ CBTProc:                                    │
//    │   │    │   │   1. OpenFileMapping("Local\WindowGuardCBT")│
//    │   │    │   │   2. Читает координаты primary              │
//    │   │    │   │   3. Модифицирует CREATESTRUCT.x/.y         │
//    │   │    │   │   4. InterlockedIncrement(counter)          │
//    │   │    │   │                                              │
//    │   │    │   └─ Окно создаётся на primary мониторе!        │
//    │   │                                                      │
//    │   └──────────────────────────────────────────────────────┘
//    │
//    └─ Timer: ReadInterceptCount() → tooltip "перехвачено: N"
//
// ═══════════════════════════════════════════════════════════════════
//  ОГРАНИЧЕНИЯ CBT HOOK
// ═══════════════════════════════════════════════════════════════════
//
//  1. Битность: 64-бит DLL хукает только 64-бит процессы.
//     Для 32-бит нужен отдельный 32-бит процесс-помощник
//     с wghook32.dll и своим SetWindowsHookEx.
//
//  2. UWP/Store приложения: AppContainer sandbox блокирует
//     инжекцию DLL. Для них работает только WinEventHook.
//
//  3. Производительность: CBT hook вызывается при КАЖДОМ
//     создании/активации/перемещении окна во ВСЕХ процессах.
//     Наша CBTProc быстрая (только HCBT_CREATEWND), но сам
//     механизм глобального хука добавляет overhead.
//
//  4. Антивирусы: глобальный хук + DLL инжекция — типичное
//     поведение малвари. Некоторые AV могут ругаться.
//
// ═══════════════════════════════════════════════════════════════════
//  ДРУГИЕ ИДЕИ
// ═══════════════════════════════════════════════════════════════════
//
//  A. Окно-якорь: невидимое окно на primary как foreground anchor
//  B. Патч ShellExecuteEx в explorer.exe через Detours/MinHook
//  C. ETW провайдер Microsoft-Windows-Win32k для мгновенных событий
//  D. SSDT hook NtUserCreateWindowEx (нужен kernel driver)
//  E. AppInit_DLLs через реестр (RequireSignedAppInit_DLLs!)
//  F. IFEO Debugger для конкретных exe
//  G. WMI подписка на Win32_Process для раннего PID-хука