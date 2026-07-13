@echo off
setlocal

cd /d "%~dp0"

if not defined JAVA_HOME set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"

echo ==================================================
echo Building Inline Hook Invalidate
echo JAVA_HOME=%JAVA_HOME%
echo ==================================================

call gradlew.bat assembleModuleZip --console=plain
if errorlevel 1 (
    echo.
    echo ==================================================
    echo BUILD FAILED
    echo ==================================================
    exit /b 1
)

echo.
echo ==================================================
echo BUILD SUCCEEDED
echo Zip output: %~dp0release\InlineHookInvalidate.zip
echo ==================================================

endlocal
