<?php

/*
 * export.php -- compact, capped view of the main op_array used to print the
 * console summary after each dump. This is a quick human overview, not the
 * authoritative output (that is the IR JSON). Depends on values.php, ir.php.
 */

function export_op_array(array $opArray)
{
    $maxExportedLiterals = 60;
    $maxExportedOpcodes = 120;
    $opcodes = isset($opArray['opcodes']) && is_array($opArray['opcodes']) ? $opArray['opcodes'] : array();
    $literals = isset($opArray['literals']) && is_array($opArray['literals']) ? $opArray['literals'] : array();
    $vars = isset($opArray['vars']) && is_array($opArray['vars']) ? $opArray['vars'] : array();
    $closureReport = isset($opArray['closure_report']) && is_array($opArray['closure_report']) ? $opArray['closure_report'] : array();

    $exportedOpcodes = array();
    foreach ($opcodes as $index => $opcode) {
        if ($index >= $maxExportedOpcodes) {
            break;
        }
        $exportedOpcodes[] = array(
            'index' => $index,
            'line' => isset($opcode['lineno']) ? $opcode['lineno'] : null,
            'opcode' => isset($opcode['opcode']) ? $opcode['opcode'] : null,
            'opcode_name' => opcode_label($opcode),
            'op1_type' => isset($opcode['op1_type']) ? $opcode['op1_type'] : null,
            'op2_type' => isset($opcode['op2_type']) ? $opcode['op2_type'] : null,
            'result_type' => isset($opcode['result_type']) ? $opcode['result_type'] : null,
            'extended_value' => isset($opcode['extended_value']) ? $opcode['extended_value'] : null,
        );
    }

    $exportedLiterals = array();
    foreach ($literals as $index => $literal) {
        if ($index >= $maxExportedLiterals) {
            break;
        }
        $exportedLiterals[] = array(
            'index' => $index,
            'value' => describe_value($literal),
        );
    }

    return array(
        'function_name' => isset($opArray['function_name']) ? $opArray['function_name'] : null,
        'line_start' => isset($opArray['line_start']) ? $opArray['line_start'] : null,
        'line_end' => isset($opArray['line_end']) ? $opArray['line_end'] : null,
        'opcode_count' => count($opcodes),
        'literal_count' => count($literals),
        'exported_opcode_count' => count($exportedOpcodes),
        'exported_literal_count' => count($exportedLiterals),
        'var_count' => count($vars),
        'vars' => array_values($vars),
        'closure_report' => $closureReport,
        'literals' => $exportedLiterals,
        'opcodes' => $exportedOpcodes,
    );
}

function build_export_dump($sourcePath, array $dump)
{
    $opArray = isset($dump['op_array']) && is_array($dump['op_array']) ? $dump['op_array'] : array();
    $export = array(
        'source_file' => $sourcePath,
        'main' => export_op_array($opArray),
        'functions' => array(),
        'classes' => array(),
    );

    return $export;
}

function print_summary($path, array $export)
{
    $main = isset($export['main']) && is_array($export['main']) ? $export['main'] : array();
    $opcodes = isset($main['opcodes']) && is_array($main['opcodes']) ? $main['opcodes'] : array();
    $vars = isset($main['vars']) && is_array($main['vars']) ? $main['vars'] : array();

    echo "== ", $path, " ==\n";
    echo "lines: ", isset($main['line_start']) ? $main['line_start'] : '?', "-", isset($main['line_end']) ? $main['line_end'] : '?', "\n";
    echo "opcodes: ", isset($main['opcode_count']) ? $main['opcode_count'] : count($opcodes), " | literals: ", isset($main['literal_count']) ? $main['literal_count'] : 0, " | vars: ", count($vars), "\n";
    echo "exported preview: ", count($opcodes), " opcodes | ", isset($main['exported_literal_count']) ? $main['exported_literal_count'] : 0, " literals\n";
    if (isset($main['closure_report']) && is_array($main['closure_report'])) {
        $declared = isset($main['closure_report']['declared_lambdas']) ? $main['closure_report']['declared_lambdas'] : 0;
        $dumped = isset($main['closure_report']['dumped_closure_op_arrays']) ? $main['closure_report']['dumped_closure_op_arrays'] : 0;
        $missing = isset($main['closure_report']['missing']) ? $main['closure_report']['missing'] : 0;
        echo "closures: declared=", $declared, " | dumped=", $dumped, " | missing=", $missing, "\n";
    }

    if ($vars) {
        echo "vars: ", implode(', ', array_slice($vars, 0, 12));
        if (count($vars) > 12) {
            echo ", ...";
        }
        echo "\n";
    }

    echo "first opcodes:\n";
    $limit = min(12, count($opcodes));
    for ($index = 0; $index < $limit; $index++) {
        $opcode = $opcodes[$index];
        $line = isset($opcode['line']) ? $opcode['line'] : '?';
        $numeric = isset($opcode['opcode']) ? $opcode['opcode'] : '?';
        $label = isset($opcode['opcode_name']) ? $opcode['opcode_name'] : '#?';
        echo sprintf("  [%03d] line %-4s %-24s (%s)\n", $index, $line, $label, $numeric);
    }

    echo "\n";
}
