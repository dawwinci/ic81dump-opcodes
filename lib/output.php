<?php

/*
 * output.php -- target resolution and writing the two dump artifacts:
 *   <file>.opcodes.json  -- the icdump-ir-v1 structure (authoritative)
 *   <file>.opcodes.txt   -- print_r of the normalized raw dump (human view)
 *
 * Honors OPCODEDUMP_OUTPUT_DIR to redirect both outputs. Depends on
 * normalize.php, ir.php, export.php.
 */

function resolve_target($path, $scriptDir)
{
    $candidates = array(
        $path,
        $scriptDir . DIRECTORY_SEPARATOR . $path,
        getcwd() . DIRECTORY_SEPARATOR . $path,
    );

    foreach ($candidates as $candidate) {
        $real = realpath($candidate);
        if ($real !== false && is_file($real)) {
            return $real;
        }
    }

    return false;
}

function dump_output_path($path)
{
    $outputDir = getenv('OPCODEDUMP_OUTPUT_DIR');
    if ($outputDir) {
        $base = preg_replace('/\.php$/i', '', basename($path));
        return rtrim($outputDir, "\\/") . DIRECTORY_SEPARATOR . $base . '.opcodes.txt';
    }
    return preg_replace('/\.php$/i', '', $path) . '.opcodes.txt';
}

function dump_json_output_path($path)
{
    $outputDir = getenv('OPCODEDUMP_OUTPUT_DIR');
    if ($outputDir) {
        $base = preg_replace('/\.php$/i', '', basename($path));
        return rtrim($outputDir, "\\/") . DIRECTORY_SEPARATOR . $base . '.opcodes.json';
    }
    return preg_replace('/\.php$/i', '', $path) . '.opcodes.json';
}

function write_dump_outputs($resolved, array $rawDump)
{
    $normalizedDump = normalize_dump($rawDump);
    $dump = prepare_dump_for_output($normalizedDump, $resolved);
    $export = build_export_dump($resolved, $dump);
    $ir = build_decompile_ir($resolved, $dump);
    $outputPath = dump_output_path($resolved);
    $jsonOutputPath = dump_json_output_path($resolved);
    $serialized = print_r($dump, true);
    $jsonFlags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $jsonFlags |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    $json = json_encode($ir, $jsonFlags);

    if ($serialized === false || file_put_contents($outputPath, $serialized . PHP_EOL) === false) {
        fwrite(STDERR, "Failed to write dump file: {$outputPath}\n");
        return false;
    }

    if ($json === false || file_put_contents($jsonOutputPath, $json . PHP_EOL) === false) {
        fwrite(STDERR, "Failed to write JSON dump file: {$jsonOutputPath}\n");
        return false;
    }

    print_summary($resolved, $export);
    echo "saved: ", $outputPath, "\n";
    echo "saved: ", $jsonOutputPath, "\n\n";
    return true;
}
