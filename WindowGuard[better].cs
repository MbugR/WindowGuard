using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

class WindowGuard
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
    static extern int GetClassName(IntPtr h, System.Text.StringBuilder sb, int max);

    delegate bool EnumWndProc(IntPtr h, IntPtr lp);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X, Y; }

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

    const uint EVENT_OBJECT_CREATE         = 0x8000;
    const uint EVENT_OBJECT_SHOW           = 0x8002;
    const uint EVENT_OBJECT_LOCATIONCHANGE = 0x800B;
    const uint EVENT_SYSTEM_MOVESIZESTART  = 0x000A;
    const uint EVENT_SYSTEM_MOVESIZEEND    = 0x000B;
    const uint EVENT_SYSTEM_FOREGROUND     = 0x0003;
    const int  VK_SHIFT                    = 0x10;
    const int  VK_LWIN                     = 0x5B;
    const int  VK_RWIN                     = 0x5C;
    const int  SW_SHOWNOACTIVATE           = 4;
    const uint WINEVENT_OUTOFCONTEXT       = 0;
    const uint WINEVENT_SKIPOWNPROCESS     = 2;
    const int  GWL_STYLE                   = -16;
    const int  GWL_EXSTYLE                 = -20;
    const int  WS_CAPTION                  = 0x00C00000;
    const int  WS_POPUP                    = unchecked((int)0x80000000);
    const int  WS_CHILD                    = 0x40000000;
    const int  WS_EX_TOOLWINDOW            = 0x00000080;
    const int  WS_EX_NOACTIVATE            = 0x08000000;
    const int  WS_EX_APPWINDOW             = 0x00040000;
    const uint MONITOR_DEFAULTTOPRIMARY    = 1;
    const uint MONITOR_DEFAULTTONEAREST    = 2;
    const uint SWP_NOSIZE                  = 0x0001;
    const uint SWP_NOZORDER                = 0x0004;
    const uint SWP_NOACTIVATE              = 0x0010;
    const uint SWP_NOSENDCHANGING          = 0x0400;
    const uint SWP_ASYNCWINDOWPOS          = 0x4000;
    const uint RDW_INVALIDATE              = 0x0001;
    const uint RDW_UPDATENOW               = 0x0100;
    const uint RDW_ALLCHILDREN             = 0x0080;

    #endregion

    static IntPtr _primary;
    static readonly Dictionary<IntPtr, IntPtr>   _approved   = new Dictionary<IntPtr, IntPtr>();
    static readonly HashSet<IntPtr>              _dragging   = new HashSet<IntPtr>();
    static readonly Dictionary<IntPtr, DateTime> _wgMoved    = new Dictionary<IntPtr, DateTime>();
    // Окна которые мы уже переместили мгновенно — повторная проверка через короткий интервал
    static readonly Dictionary<IntPtr, int>      _recheck    = new Dictionary<IntPtr, int>();
    const int WG_MOVED_GRACE_MS   = 1500;
    const int RECHECK_ATTEMPTS    = 3;
    const int RECHECK_INTERVAL_MS = 150;

    static DateTime _displayChangedAt = DateTime.MinValue;
    const int DISPLAY_SETTLE_MS = 4000;
    static bool _paused = false;

    // Классы окон которые нужно игнорировать (системные, всплывающие)
    static readonly HashSet<string> _ignoreClasses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "tooltips_class32", "Shell_TrayWnd", "DV2ControlHost",
        "Shell_SecondaryTrayWnd", "Progman", "WorkerW",
        "NotifyIconOverflowWindow", "Windows.UI.Core.CoreWindow",
        "#32768" // меню
    };

    static readonly List<WinEventProc> _delegates = new List<WinEventProc>();

    [STAThread]
    static void Main()
    {
        bool createdNew;
        var mutex = new Mutex(true, "WindowGuard_SingleInstance", out createdNew);
        if (!createdNew)
        {
            MessageBox.Show("WindowGuard уже запущен.", "WindowGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Application.EnableVisualStyles();
        SyncAutostartPath();

        _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);

        SystemEvents.DisplaySettingsChanged += (s, e) =>
        {
            _displayChangedAt = DateTime.UtcNow;
            _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
        };
        SystemEvents.PowerModeChanged += (s, e) =>
        {
            if (((PowerModeChangedEventArgs)e).Mode == PowerModes.Resume)
            {
                _displayChangedAt = DateTime.UtcNow;
                _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
            }
        };

        // Хуки — перехватываем создание, показ, перемещение, drag
        Hook(EVENT_OBJECT_CREATE,         EVENT_OBJECT_CREATE,         OnCreate);
        Hook(EVENT_OBJECT_SHOW,           EVENT_OBJECT_SHOW,           OnShow);
        Hook(EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_LOCATIONCHANGE, OnLocationChange);
        Hook(EVENT_SYSTEM_MOVESIZESTART,  EVENT_SYSTEM_MOVESIZESTART,  OnDragStart);
        Hook(EVENT_SYSTEM_MOVESIZEEND,    EVENT_SYSTEM_MOVESIZEEND,    OnDragEnd);
        Hook(EVENT_SYSTEM_FOREGROUND,     EVENT_SYSTEM_FOREGROUND,     OnForeground);

        // Запомнить уже открытые окна
        EnumWindows((h, lp) =>
        {
            if (IsReal(h))
                _approved[h] = MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST);
            return true;
        }, IntPtr.Zero);

        // Быстрый таймер для повторных проверок и очистки
        var timer = new System.Windows.Forms.Timer { Interval = 100 };
        timer.Tick += (s, e) => CheckAll();
        timer.Start();

        // Трей
        BuildTray();
        Application.Run();
        mutex.ReleaseMutex();
    }

    static void Hook(uint eMin, uint eMax, WinEventProc proc)
    {
        _delegates.Add(proc);
        SetWinEventHook(eMin, eMax, IntPtr.Zero, proc, 0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    }

    static string GetClass(IntPtr hwnd)
    {
        var sb = new System.Text.StringBuilder(256);
        GetClassName(hwnd, sb, sb.Capacity);
        return sb.ToString();
    }

    static bool IsReal(IntPtr hwnd)
    {
        if (!IsWindow(hwnd))          return false;
        if (!IsWindowVisible(hwnd))   return false;
        if (IsIconic(hwnd))           return false;

        int style   = GetWindowLong(hwnd, GWL_STYLE);
        int exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

        // Дочернее окно — не трогаем
        if ((style & WS_CHILD) != 0) return false;

        // Без заголовка и не APPWINDOW — пропускаем
        if ((style & WS_CAPTION) == 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;

        // Tool window без APPWINDOW — пропускаем
        if ((exStyle & WS_EX_TOOLWINDOW) != 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;

        // NOACTIVATE без APPWINDOW — пропускаем (overlay, OSD)
        if ((exStyle & WS_EX_NOACTIVATE) != 0 && (exStyle & WS_EX_APPWINDOW) == 0) return false;

        // Игнорируемые классы
        string cls = GetClass(hwnd);
        if (_ignoreClasses.Contains(cls)) return false;

        return true;
    }

    // Самый ранний момент — окно создано но ещё может быть невидимым
    static void OnCreate(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused) return;
        if (obj != 0 || child != 0) return;
        // Пока просто запоминаем — окно ещё не готово
    }

    // Окно стало видимым — МГНОВЕННЫЙ перенос
    static void OnShow(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused) return;
        if (obj != 0 || child != 0) return;
        if (!IsReal(hwnd)) return;

        // Если уже отслеживаем — это не новое окно
        if (_approved.ContainsKey(hwnd)) return;

        // Новое окно — сразу назначаем на primary
        _approved[hwnd] = _primary;

        var mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (mon != _primary)
        {
            // Мгновенный перенос ДО первой отрисовки
            PutOn(hwnd, _primary, updatePlacement: true);
            // Ставим на повторную проверку — некоторые приложения
            // (Electron, CEF, WPF) двигают окно после Show
            _recheck[hwnd] = RECHECK_ATTEMPTS;
        }
    }

    // Foreground сменился — если новое незнакомое окно, перехватываем
    static void OnForeground(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused) return;
        if (hwnd == IntPtr.Zero) return;
        if (_approved.ContainsKey(hwnd)) return;
        if (!IsReal(hwnd)) return;

        _approved[hwnd] = _primary;

        if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
        {
            PutOn(hwnd, _primary, updatePlacement: true);
            _recheck[hwnd] = RECHECK_ATTEMPTS;
        }
    }

    static void OnLocationChange(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        if (_paused) return;
        if (obj != 0 || child != 0) return;
        if (!_approved.ContainsKey(hwnd)) return;
        if (_dragging.Contains(hwnd)) return;
        if (!IsReal(hwnd)) return;

        var newMonitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (newMonitor == _approved[hwnd]) return;

        // Win+Shift+Arrow — разрешаем
        bool winHeld   = (GetAsyncKeyState(VK_LWIN)  & 0x8000) != 0
                      || (GetAsyncKeyState(VK_RWIN)  & 0x8000) != 0;
        bool shiftHeld = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

        if (winHeld && shiftHeld)
        {
            _approved[hwnd] = newMonitor;
            return;
        }

        // Программное перемещение — возвращаем назад
        PutOn(hwnd, _approved[hwnd], updatePlacement: false);
    }

    static void OnDragStart(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        _dragging.Add(hwnd);
    }

    static void OnDragEnd(IntPtr hook, uint evType, IntPtr hwnd,
        int obj, int child, uint tid, uint time)
    {
        _dragging.Remove(hwnd);
        if (IsWindow(hwnd))
            _approved[hwnd] = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    }

    static void MoveAllToPrimary()
    {
        _primary = MonitorFromWindow(IntPtr.Zero, MONITOR_DEFAULTTOPRIMARY);
        foreach (var h in new List<IntPtr>(_approved.Keys))
        {
            _approved[h] = _primary;
            if (IsReal(h) && MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) != _primary)
                PutOn(h, _primary, updatePlacement: true);
        }
    }

    static void CheckAll()
    {
        if (_paused) return;
        var now = DateTime.UtcNow;

        // Ждём стабилизации после DisplayChange / Resume
        if (_displayChangedAt != DateTime.MinValue)
        {
            if ((now - _displayChangedAt).TotalMilliseconds >= DISPLAY_SETTLE_MS)
            {
                _displayChangedAt = DateTime.MinValue;
                MoveAllToPrimary();
            }
            return; // пока монитор не стабилен — не проверяем
        }

        // Повторные проверки для "упрямых" окон
        var recheckDone = new List<IntPtr>();
        foreach (var kv in new Dictionary<IntPtr, int>(_recheck))
        {
            IntPtr hwnd = kv.Key;
            if (!IsWindow(hwnd) || !IsWindowVisible(hwnd))
            {
                recheckDone.Add(hwnd);
                continue;
            }

            if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != _primary)
            {
                PutOn(hwnd, _primary, updatePlacement: false);
                _recheck[hwnd] = kv.Value - 1;
                if (kv.Value - 1 <= 0) recheckDone.Add(hwnd);
            }
            else
            {
                recheckDone.Add(hwnd); // уже на месте
            }
        }
        foreach (var h in recheckDone) _recheck.Remove(h);

        // Основная проверка — несанкционированные перемещения
        var dead = new List<IntPtr>();
        foreach (var kv in new Dictionary<IntPtr, IntPtr>(_approved))
        {
            IntPtr hwnd = kv.Key;

            if (!IsWindow(hwnd))
            {
                dead.Add(hwnd);
                continue;
            }

            if (!IsWindowVisible(hwnd))
            {
                // Окно скрылось после нашего перемещения — восстанавливаем
                DateTime movedAt;
                if (_wgMoved.TryGetValue(hwnd, out movedAt) &&
                    (now - movedAt).TotalMilliseconds < WG_MOVED_GRACE_MS)
                {
                    ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                    continue;
                }
                dead.Add(hwnd);
                continue;
            }

            if (_dragging.Contains(hwnd))  continue;
            if (_recheck.ContainsKey(hwnd)) continue;
            if (IsIconic(hwnd))            continue;

            if (MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST) != kv.Value)
                PutOn(hwnd, kv.Value, updatePlacement: false);
        }

        foreach (var h in dead)
        {
            _approved.Remove(h);
            _dragging.Remove(h);
            _recheck.Remove(h);
            _wgMoved.Remove(h);
        }

        // Чистка _wgMoved
        var expired = new List<IntPtr>();
        foreach (var kv in _wgMoved)
            if ((now - kv.Value).TotalMilliseconds >= WG_MOVED_GRACE_MS)
                expired.Add(kv.Key);
        foreach (var h in expired) _wgMoved.Remove(h);
    }

    static void PutOn(IntPtr hwnd, IntPtr monitor, bool updatePlacement)
    {
        var mi = new MONITORINFO { cbSize = Marshal.SizeOf(typeof(MONITORINFO)) };
        if (!GetMonitorInfo(monitor, ref mi)) return;

        RECT r;
        GetWindowRect(hwnd, out r);
        int w = r.Right  - r.Left;
        int h = r.Bottom - r.Top;

        int areaW = mi.rcWork.Right  - mi.rcWork.Left;
        int areaH = mi.rcWork.Bottom - mi.rcWork.Top;

        // Если окно больше рабочей области — вписываем
        if (w > areaW) w = areaW;
        if (h > areaH) h = areaH;

        int x = mi.rcWork.Left + Math.Max(0, (areaW - w) / 2);
        int y = mi.rcWork.Top  + Math.Max(0, (areaH - h) / 2);

        if (updatePlacement)
        {
            var wp = new WINDOWPLACEMENT { length = Marshal.SizeOf(typeof(WINDOWPLACEMENT)) };
            if (GetWindowPlacement(hwnd, ref wp))
            {
                wp.rcNormalPosition = new RECT
                {
                    Left = x, Top = y, Right = x + w, Bottom = y + h
                };
                SetWindowPlacement(hwnd, ref wp);
            }
        }

        if (!IsIconic(hwnd))
        {
            _wgMoved[hwnd] = DateTime.UtcNow;
            SetWindowPos(hwnd, IntPtr.Zero, x, y, w, h,
                SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSENDCHANGING | SWP_ASYNCWINDOWPOS);

            RedrawWindow(hwnd, IntPtr.Zero, IntPtr.Zero,
                RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        }
    }

    #region Tray

    static void BuildTray()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("WindowGuard — активен", null, null).Enabled = false;
        menu.Items.Add("-");

        var autoStartItem = new ToolStripMenuItem("Автозапуск с Windows")
        { Checked = IsAutostart() };
        autoStartItem.Click += (s, e) =>
        {
            SetAutostart(!autoStartItem.Checked);
            autoStartItem.Checked = IsAutostart();
        };
        menu.Items.Add(autoStartItem);

        menu.Items.Add("Перенести все на основной", null, (s, e) => MoveAllToPrimary());

        var pauseItem = new ToolStripMenuItem("Пауза") { CheckOnClick = true };
        pauseItem.CheckedChanged += (s, e) => _paused = pauseItem.Checked;
        menu.Items.Add(pauseItem);

        menu.Items.Add("Перезапустить проводник", null, (s, e) =>
        {
            foreach (var p in System.Diagnostics.Process.GetProcessesByName("explorer"))
                p.Kill();
            System.Diagnostics.Process.Start("explorer.exe");
        });
        menu.Items.Add("-");
        menu.Items.Add("Выход", null, (s, e) => Application.Exit());

        var tray = new NotifyIcon
        {
            Text             = "WindowGuard",
            Icon             = SystemIcons.Shield,
            Visible          = true,
            ContextMenuStrip = menu
        };
        tray.DoubleClick += (s, e) =>
            MessageBox.Show(
                "WindowGuard работает.\n\n" +
                "• Мгновенный перенос новых окон на основной монитор\n" +
                "• Блокировка программных перемещений\n" +
                "• Win+Shift+Arrow разрешён\n" +
                "• Ручное перетаскивание разрешено",
                "WindowGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    #endregion

    #region Autostart

    const string RUN_KEY  = @"Software\Microsoft\Windows\CurrentVersion\Run";
    const string APP_NAME = "WindowGuard";

    static bool IsAutostart()
    {
        using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY, false))
            return key?.GetValue(APP_NAME) != null;
    }

    static void SetAutostart(bool enable)
    {
        using (var key = Registry.CurrentUser.OpenSubKey(RUN_KEY, true))
        {
            if (key == null) return;
            if (enable) key.SetValue(APP_NAME, Application.ExecutablePath);
            else        key.DeleteValue(APP_NAME, false);
        }
    }

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

    #endregion
}