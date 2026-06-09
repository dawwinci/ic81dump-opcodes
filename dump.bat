@echo off
setlocal enabledelayedexpansion
:: ----------------------------------------------------------------
:: dump.bat -- full Zend opcode dump for ionCube-encoded PHP 8.1 files
::
:: Usage:
::   dump.bat path\to\encoded.php [more.php ...]
::
:: Output (next to each input file, or in OPCODEDUMP_OUTPUT_DIR):
::   <file>.opcodes.json  -- structured IR (op_arrays, literals, CFG, analysis)
::   <file>.opcodes.txt   -- human-readable print_r dump
::
:: How it works (PHP 8.1 / ionCube loader 8.1):
::   The loader runs encoded functions through its own VM loop and only
::   materializes decrypted opcodes during dispatch. OPCODEDUMP_RUNTIME_MATERIALIZE
::   drives each function through that loop with the body skipped (no side
::   effects), and snapshots {main} through the loader's direct op_array
::   materializer before restoring the root op_array.
:: ----------------------------------------------------------------
set SCRIPT_DIR=%~dp0
set PHP=%SCRIPT_DIR%runtime\php.exe
set PHP_INI=%SCRIPT_DIR%runtime\php.ini
set DUMPER=%SCRIPT_DIR%opcodedump.php

:: Materialize encoded main + functions (safe: snapshots are copied, bodies skipped).
set OPCODEDUMP_RUNTIME_MATERIALIZE=1

if not exist "%PHP%" (
    echo ERROR: runtime\php.exe not found. Keep dump.bat inside the project folder.
    exit /b 1
)
if "%~1"=="" (
    echo Usage: dump.bat path\to\encoded.php [more.php ...]
    exit /b 1
)

set EXITCODE=0
:next_target
if "%~1"=="" goto done
set TARGET=%~1
set OUT_JSON=%~dpn1.opcodes.json
set OUT_TXT=%~dpn1.opcodes.txt
if exist "%OUT_JSON%" del /f /q "%OUT_JSON%" >nul 2>nul
if exist "%OUT_TXT%"  del /f /q "%OUT_TXT%"  >nul 2>nul

echo [dump] %TARGET%
"%PHP%" -c "%PHP_INI%" "%DUMPER%" "%TARGET%"
if exist "%OUT_JSON%" (
    echo [dump] done: %OUT_JSON%
) else (
    echo ERROR: dump did not produce %OUT_JSON%
    set EXITCODE=1
)

shift
goto next_target

:done
endlocal & exit /b %EXITCODE%
