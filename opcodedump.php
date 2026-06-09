<?php

/*
 * opcodedump.php -- CLI entry point for the ionCube PHP 8.1 opcode dumper.
 *
 * Drives the `opcodedump` C extension (dasm_file) over one or more target
 * files and writes, next to each, a structured IR JSON plus a human-readable
 * print_r TXT. The heavy lifting lives in lib/*.php:
 *
 *   lib/values.php     primitive value helpers + generic array utils
 *   lib/flags.php      Zend bitmask / extended_value decoders
 *   lib/stub.php       decode-coaxing scaffolding (stub class, autoload, dirs)
 *   lib/normalize.php  raw-dump cleanup for the TXT output
 *   lib/ir.php         icdump-ir-v1 construction (the JSON output)
 *   lib/export.php     compact console summary
 *   lib/output.php     target resolution + writing both artifacts
 */

if (!extension_loaded('opcodedump')) {
    fwrite(STDERR, "Extension 'opcodedump' is not loaded.\n");
    exit(1);
}

$libDir = __DIR__ . DIRECTORY_SEPARATOR . 'lib';
require $libDir . DIRECTORY_SEPARATOR . 'values.php';
require $libDir . DIRECTORY_SEPARATOR . 'flags.php';
require $libDir . DIRECTORY_SEPARATOR . 'stub.php';
require $libDir . DIRECTORY_SEPARATOR . 'normalize.php';
require $libDir . DIRECTORY_SEPARATOR . 'ir.php';
require $libDir . DIRECTORY_SEPARATOR . 'export.php';
require $libDir . DIRECTORY_SEPARATOR . 'output.php';

$scriptDir = __DIR__;
$targets = array_slice($argv, 1);

if (!$targets) {
    $targets = array(
        $scriptDir . DIRECTORY_SEPARATOR . 'demo.php',
    );
}

$exitCode = 0;

register_stub_autoload();

foreach ($targets as $target) {
    $resolved = resolve_target($target, $scriptDir);
    if ($resolved === false) {
        fwrite(STDERR, "Cannot find file: {$target}\n");
        $exitCode = 1;
        continue;
    }

    opcodedump_autodefine_opencart_dirs($resolved);
    $rawDump = dasm_file($resolved);
    if (!write_dump_outputs($resolved, $rawDump)) {
        $exitCode = 1;
        continue;
    }
}

exit($exitCode);
