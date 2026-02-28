using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

class MonitorLock
{
    #region P/Invoke

    delegate void WinEventProc(IntPtr hook, uint evType, IntPtr hwnd,
        int idObject, int idChild, uint thread, uint time);

    [DllImport("user32.dll")]
    static extern IntPtr SetWinEventHook(uint eMin, uint eMax, IntPtr hMod,
        WinEventProc proc, uint pid, uint tid, uint flags);

    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] static extern int  GetWindowLong(IntPtr h, int i);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr ins,
        int x, int y, int cx, int cy, uint f);
    [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr h, uint dfl);
    [DllImport("user32.dll")] static extern bool GetMonitorInfo(IntPtr m, ref MONITORINFO mi);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWndProc proc, IntPtr lp);
    [DllImport("user32.dll")] static extern bool RedrawWindow(IntPtr h, IntPtr rect, IntPtr rgn, uint flags);
    [DllImport("user32.dll")] static extern bool GetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);
    [DllImport("user32.dll")] static extern bool SetWindowPlacement(IntPtr h, ref WINDOWPLACEMENT wp);

    delegate bool EnumWndProc(IntPtr h, IntPtr lp);

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    struct POINT { public int X, Y; }

    // Хранит текущее состояние окна включая rcNormalPosition —
    // координаты куда окно возвращается при разворачивании из свёрнутого
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
    struct MONITORINFO
    {
        public int  cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    const uint EVENT_OBJECT_SHOW           = 0x8002;
    const uint EVENT_SYSTEM_MOVESIZESTART  = 0x000A;
    const uint EVENT_SYSTEM_MOVESIZEEND    = 0x000B;
    const uint WINEVENT_OUTOFCONTEXT       = 0;
    const uint WINEVENT_SKIPOWNPROCESS     = 2;
    const int  GWL_STYLE                   = -16;
    const int  GWL_EXSTYLE                 = -20;
    const int  WS_CAPTION                  = 0x00C00000;
    const int  WS_EX_TOOLWINDOW            = 0x00000080;
    const uint MONITOR_DEFAULTTOPRIMARY    = 1;
    const uint MONITOR_DEFAULTTONEAREST    = 2;
    const uint SWP_NOSIZE                  = 0x0001;
    const uint SWP_NOZORDER               = 0x0004;
    const uint SWP_NOACTIVATE             = 0x0010;
    const uint SWP_NOSENDCHANGING         = 0x0400; // не посылать WM_WINDOWPOSCHANGING
    const uint RDW_INVALIDATE             = 0x0001;
    const uint RDW_UPDATENOW              = 0x0100;
    const uint RDW_ALLCHILDREN            = 0x0080;

    // Задержка перед переносом нового окна (мс)
    const int NEW_WINDOW_DELAY_MS = 300;

    #endregion

    static IntPtr _primary;
    static readonly Dictionary<IntPtr, IntPtr>   _approved   = new Dictionary<IntPtr, IntPtr>();
    static readonly HashSet<IntPtr>              _dragging   = new HashSet<IntPtr>();
    // Новые окна ждут переноса — даём приложению время инициализироваться
    static readonly Dictionary<IntPtr, DateTime> _pendingNew = new Dictionary<IntPtr, DateTime>();
    // Keep delegates alive so GC doesn't collect them
    static readonly List<WinEventProc> _delegates = new List<WinEventProc>();

    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();

        SyncAutostartPath();

        _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);

        Hook(EVENT_OBJECT_SHOW,          EVENT_OBJECT_SHOW,          OnShow);
        Hook(EVENT_SYSTEM_MOVESIZESTART, EVENT_SYSTEM_MOVESIZESTART, OnDragStart);
        Hook(EVENT_SYSTEM_MOVESIZEEND,   EVENT_SYSTEM_MOVESIZEEND,   OnDragEnd);

        // Запомнить уже открытые окна — не трогать их, просто зафиксировать текущий монитор
        EnumWindows((h, lp) =>
        {
            if (IsReal(h))
                _approved[h] = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
            return true;
        }, IntPtr.Zero);

        var timer = new Timer { Interval = 200 };
        timer.Tick += (s, e) => CheckAll();
        timer.Start();

        // Трей
        var menu = new ContextMenuStrip();
        menu.Items.Add("MonitorLock  —  активен", null, null).Enabled = false;
        menu.Items.Add("-");

        var autoStartItem = new ToolStripMenuItem("Автозапуск с Windows");
        autoStartItem.Checked = IsAutostart();
        autoStartItem.Click += (s, e) =>
        {
            SetAutostart(!autoStartItem.Checked);
            autoStartItem.Checked = IsAutostart();
        };
        menu.Items.Add(autoStartItem);

        menu.Items.Add("-");
        menu.Items.Add("Выход", null, (s, e) => Application.Exit());

        var tray = new NotifyIcon
        {
            Text             = "MonitorLock",
            Icon             = SystemIcons.Shield,
            Visible          = true,
            ContextMenuStrip = menu
        };
        tray.DoubleClick += (s, e) =>
            MessageBox.Show(
                "MonitorLock работает.\n\n" +
                "• Новые окна открываются на основном мониторе.\n" +
                "• Программные перемещения отменяются.\n" +
                "• Ручное перетаскивание разрешено.\n\n" +
                "Правой кнопкой по иконке → Выход.",
                "MonitorLock", MessageBoxButtons.OK, MessageBoxIcon.Information);

        Application.Run();
        tray.Visible = false;
    }

    static void Hook(uint eMin, uint eMax, WinEventProc proc)
    {
        _delegates.Add(proc);
        SetWinEventHook(eMin, eMax, IntPtr.Zero, proc, 0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    }

    // Настоящее пользовательское окно: видимое, не свёрнутое, с заголовком, не тулбар
    static bool IsReal(IntPtr hwnd)
    {
        if (!IsWindowVisible(hwnd)) return false;
        if (IsIconic(hwnd))         return false;
        if ((GetWindowLong(hwnd, GWL_STYLE)   & WS_CAPTION)      == 0) return false;
        if ((GetWindowLong(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) != 0) return false;
        return true;
    }

    // Новое окно появилось — зафиксировать и поставить в очередь переноса
    static void OnShow(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (obj != 0 || child != 0) return;
        if (!IsReal(hwnd)) return;

        _approved[hwnd] = _primary;

        if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
            _pendingNew[hwnd] = DateTime.UtcNow;
    }

    // Пользователь начал тащить окно
    static void OnDragStart(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        _dragging.Add(hwnd);
    }

    // Пользователь отпустил окно — запомнить новый монитор как разрешённый
    static void OnDragEnd(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        _dragging.Remove(hwnd);
        _approved[hwnd] = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    }

    // Каждые 200 мс проверить все окна
    static void CheckAll()
    {
        var now = DateTime.UtcNow;

        // Обработать отложенные новые окна
        var ready = new List<IntPtr>();
        foreach (var kv in _pendingNew)
            if ((now - kv.Value).TotalMilliseconds >= NEW_WINDOW_DELAY_MS)
                ready.Add(kv.Key);
        foreach (var h in ready)
        {
            _pendingNew.Remove(h);
            if (!IsWindow(h)) continue;
            if (IsReal(h) && MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) != _primary)
                PutOn(h, _primary);
        }

        // Проверить все известные окна на несанкционированное перемещение
        var dead = new List<IntPtr>();
        foreach (var kv in _approved)
        {
            IntPtr hwnd = kv.Key;

            if (!IsWindowVisible(hwnd))        { dead.Add(hwnd); continue; }
            if (_dragging.Contains(hwnd))      continue;
            if (_pendingNew.ContainsKey(hwnd)) continue;
            if (IsIconic(hwnd))                continue;

            if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != kv.Value)
                PutOn(hwnd, kv.Value);
        }

        foreach (var h in dead)
        {
            _approved.Remove(h);
            _dragging.Remove(h);
            _pendingNew.Remove(h);
        }
    }

    // Переместить окно по центру указанного монитора
    static void PutOn(IntPtr hwnd, IntPtr monitor)
    {
        var mi = new MONITORINFO { cbSize = Marshal.SizeOf(typeof(MONITORINFO)) };
        if (!GetMonitorInfo(monitor, ref mi)) return;

        RECT r;
        GetWindowRect(hwnd, out r);
        int w = r.Right  - r.Left;
        int h = r.Bottom - r.Top;

        int areaW = mi.rcWork.Right  - mi.rcWork.Left;
        int areaH = mi.rcWork.Bottom - mi.rcWork.Top;

        int x = mi.rcWork.Left + Math.Max(0, (areaW - w) / 2);
        int y = mi.rcWork.Top  + Math.Max(0, (areaH - h) / 2);

        // SetWindowPlacement обновляет rcNormalPosition — позицию восстановления из свёрнутого
        var wp = new WINDOWPLACEMENT { length = Marshal.SizeOf(typeof(WINDOWPLACEMENT)) };
        if (GetWindowPlacement(hwnd, ref wp))
        {
            wp.rcNormalPosition = new RECT { Left = x, Top = y, Right = x + w, Bottom = y + h };
            SetWindowPlacement(hwnd, ref wp);
        }

        // SWP_NOSENDCHANGING подавляет WM_WINDOWPOSCHANGING — сообщение через которое
        // некоторые приложения (Telegram и др.) обнаруживают программный перенос
        if (!IsIconic(hwnd))
        {
            SetWindowPos(hwnd, IntPtr.Zero, x, y, 0, 0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING);

            RedrawWindow(hwnd, IntPtr.Zero, IntPtr.Zero,
                RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
    }

    const string RUN_KEY = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string APP_NAME = "MonitorLock";

    static bool IsAutostart()
    {
        using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY, false))
            return key != null && key.GetValue(APP_NAME) != null;
    }

    static void SetAutostart(bool enable)
    {
        using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY, true))
        {
            if (key == null) return;
            if (enable)
                key.SetValue(APP_NAME, Application.ExecutablePath);
            else
                key.DeleteValue(APP_NAME, false);
        }
    }

    // Если автозапуск включён, но путь устарел (файл переместили) — обновить
    static void SyncAutostartPath()
    {
        using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY, true))
        {
            if (key == null) return;
            var stored = key.GetValue(APP_NAME) as string;
            if (stored != null && stored != Application.ExecutablePath)
                key.SetValue(APP_NAME, Application.ExecutablePath);
        }
    }
}
