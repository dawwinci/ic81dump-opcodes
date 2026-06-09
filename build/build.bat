@echo off
setlocal
:: ----------------------------------------------------------------
:: build.bat  --  compile php_opcodedump.dll  (PHP 8.1 NTS x86 VS16)
::
:: Requirements:
::   1. Visual Studio 2019 Build Tools (VS16 / MSVC 14.2x) x86 native tools
::   2. PHP 8.1.34 NTS x86 devel pack extracted to:
::      build\devel\php-8.1.34-devel-vs16-x86\
:: ----------------------------------------------------------------
set SCRIPT_DIR=%~dp0
set SRC=%SCRIPT_DIR%..\src
set OUT=%SCRIPT_DIR%out
set DEVEL=%SCRIPT_DIR%devel\php-8.1.34-devel-vs16-x86
set PHP_INC=%DEVEL%\include

if not exist "%PHP_INC%\main\php.h" (
    echo ERROR: PHP 8.1 devel headers not found at %PHP_INC%\main\php.h
    exit /b 1
)

if not exist "%OUT%" mkdir "%OUT%"

call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars32.bat" > nul 2>&1
where cl.exe > nul 2>&1
if errorlevel 1 (
    echo ERROR: vcvars32.bat not found. Install Visual Studio 2019 Build Tools.
    exit /b 1
)

echo [1/2] Compiling opcodedump.c ...
cl.exe /nologo /c /MD /O2 /W3 /wd4996 ^
    /DWIN32 /D_WINDOWS /DZEND_WIN32=1 /DPHP_WIN32=1 ^
    /DCOMPILE_DL_OPCODEDUMP /DZEND_DEBUG=0 ^
    /I"%PHP_INC%" /I"%PHP_INC%\main" /I"%PHP_INC%\Zend" ^
    /I"%PHP_INC%\TSRM" /I"%PHP_INC%\win32" /I"%PHP_INC%\ext" ^
    /Fo"%OUT%\opcodedump.obj" ^
    "%SRC%\opcodedump.c"
if errorlevel 1 ( echo ERROR: Compilation failed. & exit /b 1 )

echo [2/2] Linking php_opcodedump.dll ...
link.exe /nologo /DLL ^
    /OUT:"%OUT%\php_opcodedump.dll" ^
    /LIBPATH:"%DEVEL%\lib" ^
    "%OUT%\opcodedump.obj" ^
    php8.lib
if errorlevel 1 ( echo ERROR: Linking failed. & exit /b 1 )

echo.
echo SUCCESS: %OUT%\php_opcodedump.dll
echo Copy it to  ..\runtime\ext\php_opcodedump.dll  to deploy.
endlocal
