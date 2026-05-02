@echo off
chcp 65001 >nul
setlocal
setlocal EnableDelayedExpansion

REM --- Java: prefer bundled JDK, fallback to system ---
if exist "%~dp0..\jre\bin\javac.exe" (
    set "JAVA_HOME=%~dp0..\jre"
) else if exist "%~dp0..\jre\bin\javac" (
    set "JAVA_HOME=%~dp0..\jre"
)
if defined JAVA_HOME set "PATH=%JAVA_HOME%\bin;%PATH%"

REM --- Burp Suite JAR ---
if not defined BURP_JAR (
    if exist "%~dp0..\BurpSuite\burpsuite_pro.jar" (
        set "BURP_JAR=%~dp0..\BurpSuite\burpsuite_pro.jar"
    ) else (
        echo [ERROR] burpsuite_pro.jar not found.
        echo         Set BURP_JAR before running:
        echo           set BURP_JAR=C:\path\to\burpsuite_pro.jar
        exit /b 1
    )
)

set "OUT_DIR=%~dp0out"
set "JAR_NAME=by-ai.jar"

echo ============================================
echo   by ai Extension Builder
echo ============================================
echo   Java:   %JAVA_HOME%
echo   Burp:   %BURP_JAR%
echo.

if not exist "%BURP_JAR%" (
    echo [ERROR] burpsuite_pro.jar not found: %BURP_JAR%
    exit /b 1
)

echo [1/3] Cleaning output directory...
if exist "%OUT_DIR%" rmdir /s /q "%OUT_DIR%"
mkdir "%OUT_DIR%"

echo [2/3] Compiling Java sources...
(
    for /r "%~dp0src\ai\burp" %%f in (*.java) do (
        set "SRC=%%f"
        echo "!SRC:\=/!"
    )
) > "%OUT_DIR%\sources.txt"

javac -cp "%BURP_JAR%" -d "%OUT_DIR%" -encoding UTF-8 "@%OUT_DIR%\sources.txt"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo [3/3] Building JAR...
REM Use jar from JAVA_HOME if available, otherwise use system PATH
if exist "%JAVA_HOME%\bin\jar.exe" (
    "%JAVA_HOME%\bin\jar.exe" cfe "%~dp0%JAR_NAME%" ai.burp.BurpAIExtension -C "%OUT_DIR%" ai
) else (
    jar cfe "%~dp0%JAR_NAME%" ai.burp.BurpAIExtension -C "%OUT_DIR%" ai
)

echo.
echo ============================================
echo   Build SUCCESS: %JAR_NAME%
echo   Load in Burp: Extender ^> Extensions ^> Add
echo ============================================

endlocal
