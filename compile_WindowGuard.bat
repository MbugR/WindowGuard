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

:: Закрываем запущенный процесс если есть
taskkill /f /im WindowGuard.exe >nul 2>&1

:: Генерируем иконку через PowerShell (системный щит)
echo Создаю иконку ...
powershell -NoProfile -Command ^
  "Add-Type -AssemblyName System.Drawing; $ico = [System.Drawing.SystemIcons]::Shield; $s = [System.IO.File]::OpenWrite('%~dp0WindowGuard.ico'); $ico.Save($s); $s.Close()"

echo Компилирую WindowGuard.cs ...
"%CSC%" /target:winexe /r:System.Windows.Forms.dll /r:System.Drawing.dll /win32icon:"%~dp0WindowGuard.ico" /out:"%~dp0WindowGuard.exe" "%~dp0WindowGuard.cs"

if %ERRORLEVEL%==0 (
    echo.
    echo  OK! WindowGuard.exe создан.
    echo  Запустите его — появится иконка в трее ^(системный лоток^).
    echo  Правой кнопкой по иконке — Выход.
    echo  Выход через секунду.
    timeout /t 1 /nobreak >nul
) else (
    echo.
    echo  ОШИБКА компиляции. Проверьте WindowGuard.cs.
    pause
)
