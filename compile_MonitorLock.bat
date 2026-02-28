@echo off
chcp 65001 >nul

:: Ищем csc.exe (компилятор C#, встроен в Windows через .NET Framework)
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe

if not exist "%CSC%" (
    echo ОШИБКА: csc.exe не найден.
    echo Убедитесь что .NET Framework 4.x установлен.
    pause
    exit /b 1
)

:: Генерируем иконку через PowerShell (системный щит)
echo Создаю иконку ...
powershell -NoProfile -Command ^
  "Add-Type -AssemblyName System.Drawing; $ico = [System.Drawing.SystemIcons]::Shield; $s = [System.IO.File]::OpenWrite('%~dp0MonitorLock.ico'); $ico.Save($s); $s.Close()"

echo Компилирую MonitorLock.cs ...
"%CSC%" /target:winexe /r:System.Windows.Forms.dll /r:System.Drawing.dll /win32icon:"%~dp0MonitorLock.ico" /out:"%~dp0MonitorLock.exe" "%~dp0MonitorLock.cs"

if %ERRORLEVEL%==0 (
    echo.
    echo  OK! MonitorLock.exe создан.
    echo  Запустите его — появится иконка в трее ^(системный лоток^).
    echo  Правой кнопкой по иконке — Выход.
) else (
    echo.
    echo  ОШИБКА компиляции. Проверьте MonitorLock.cs.
)

pause
