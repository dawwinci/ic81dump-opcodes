<?php

/*
 * normalize.php -- cleans the raw dump from the C extension into the stable,
 * readable shape used by the print_r TXT output (and consumed by the IR layer).
 *
 * The C extension occasionally emits keys with a trailing byte stripped or a
 * trailing NUL; normalize_key() canonicalises those, and the reorder_* helpers
 * give each structure a predictable key order. Depends on values.php
 * (reorder_assoc, normalize_path).
 */

function normalize_key($key)
{
    static $aliases = array(
        'function_nam' => 'function_name',
        'function_tabl' => 'function_table',
        'class_tabl' => 'class_table',
        'arg_inf' => 'arg_info',
        'doc_commen' => 'doc_comment',
        'doc_comment_le' => 'doc_comment_len',
        'op_arra' => 'op_array',
        'typ' => 'type',
        'name_le' => 'name_len',
        'class_nam' => 'class_name',
        'class_name_le' => 'class_name_len',
        'default_properties_tabl' => 'default_properties_table',
        'default_static_members_tabl' => 'default_static_members_table',
        'properties_inf' => 'properties_info',
        'offse' => 'offset',
        'flag' => 'flags',
        'op1.litera' => 'op1.literal',
        'op2.litera' => 'op2.literal',
        'result.litera' => 'result.literal',
        'handle' => 'handler',
        'opcode_inde' => 'opcode_index',
        'opcod' => 'opcode',
        'literal_inde' => 'literal_index',
        'parent_scop' => 'parent_scope',
        'closure_repor' => 'closure_report',
        'declared_lambda' => 'declared_lambdas',
        'dumped_closure_op_array' => 'dumped_closure_op_arrays',
        'decode_faile' => 'decode_failed',
        'fe_fetch_done_oplin' => 'fe_fetch_done_opline',
        'ioncube_detectio' => 'ioncube_detection',
        'loader_materialized_method' => 'loader_materialized_methods',
        'dynamic_key_protected_method' => 'dynamic_key_protected_methods',
        'missin' => 'missing',
    );

    if (!is_string($key)) {
        return $key;
    }

    $key = str_replace("\0", '', $key);

    if (isset($aliases[$key])) {
        return $aliases[$key];
    }

    return $key;
}

function normalize_dump($value)
{
    if (!is_array($value)) {
        return $value;
    }

    $normalized = array();
    foreach ($value as $key => $item) {
        $key = normalize_key($key);
        $normalized[$key] = normalize_dump($item);
    }

    return $normalized;
}

function normalize_opcode_entry(array $opcode)
{
    return reorder_assoc($opcode, array(
        'opcode',
        'opcode_raw',
        'opcode_xor_decoded',
        'resolved_opcode',
        'op1_type',
        'op2_type',
        'result_type',
        'extended_value',
        'lineno',
        'opcode_name',
        'resolved_opcode_name',
        'resolved_opcode_source',
        'ic_key_byte',
        'ic_key_dword',
        'ic_meta_flags',
        'ic_operand_flags',
        'op1_type_name',
        'op2_type_name',
        'result_type_name',
        'op1.literal',
        'op2.literal',
        'result.literal',
        'op1.cv_name',
        'op2.cv_name',
        'result.cv_name',
        'result.constant',
        'result.var',
        'result.num',
        'result.opline_num',
        'op1.constant',
        'op1.var',
        'op1.num',
        'op1.opline_num',
        'op2.constant',
        'op2.var',
        'op2.num',
        'op2.opline_num',
        'handler',
    ));
}

function normalize_arg_info_entry(array $argInfo)
{
    return reorder_assoc($argInfo, array(
        'name',
        'name_len',
        'class_name',
        'class_name_len',
        'type',
        'type_hint',
        'allow_null',
        'pass_by_reference',
        'is_variadic',
    ));
}

function normalize_property_info_entry(array $propertyInfo)
{
    return reorder_assoc($propertyInfo, array(
        'name',
        'name_len',
        'doc_comment',
        'doc_comment_len',
        'offset',
        'flags',
        'ce',
    ));
}

function normalize_op_array_entry(array $opArray)
{
    if (isset($opArray['arg_info']) && is_array($opArray['arg_info'])) {
        foreach ($opArray['arg_info'] as $index => $argInfo) {
            if (is_array($argInfo)) {
                $opArray['arg_info'][$index] = normalize_arg_info_entry($argInfo);
            }
        }
    }

    if (isset($opArray['opcodes']) && is_array($opArray['opcodes'])) {
        foreach ($opArray['opcodes'] as $index => $opcode) {
            if (is_array($opcode)) {
                $opArray['opcodes'][$index] = normalize_opcode_entry($opcode);
            }
        }
    }

    return reorder_assoc($opArray, array(
        'type',
        'function_name',
        'fn_flags',
        'arg_info',
        'num_args',
        'required_num_args',
        'refcount',
        'literals',
        'last_literal',
        'opcodes',
        'last',
        'T',
        'live_range',
        'last_live_range',
        'try_catch_array',
        'last_try_catch',
        'static_variables',
        'closures',
        'closure_report',
        'filename',
        'doc_comment',
        'doc_comment_len',
        'line_start',
        'line_end',
        'early_binding',
        'cache_size',
        'vars',
        'last_var',
        'prototype',
        'scope',
    ));
}

function normalize_function_table(array $functionTable, $sourcePath)
{
    $normalized = array();
    $normalizedSource = normalize_path($sourcePath);

    foreach ($functionTable as $name => $entry) {
        if (!is_array($entry) || !isset($entry['op_array']) || !is_array($entry['op_array'])) {
            continue;
        }

        $opArray = $entry['op_array'];
        $entryPath = isset($opArray['filename']) ? normalize_path($opArray['filename']) : null;
        if ($entryPath !== $normalizedSource && $entryPath !== normalize_path('(ionCube-protected)')) {
            continue;
        }

        $entry['op_array'] = normalize_op_array_entry($opArray);
        $normalized[$name] = reorder_assoc($entry, array('op_array'));
    }

    return $normalized;
}

function normalize_class_table(array $classTable, $sourcePath)
{
    $normalized = array();

    foreach ($classTable as $name => $classInfo) {
        if (!is_array($classInfo)) {
            continue;
        }

        // Skip classes the dumper itself fabricated (stub + autoload mocks):
        // they belong to the tooling, not to the file under analysis.
        if (opcodedump_is_synthetic_class($name)) {
            continue;
        }

        if (isset($classInfo['function_table']) && is_array($classInfo['function_table'])) {
            $classInfo['function_table'] = normalize_function_table($classInfo['function_table'], $sourcePath);
        }

        if (isset($classInfo['properties_info']) && is_array($classInfo['properties_info'])) {
            foreach ($classInfo['properties_info'] as $propName => $propInfo) {
                if (is_array($propInfo)) {
                    $classInfo['properties_info'][$propName] = normalize_property_info_entry($propInfo);
                }
            }
        }

        $normalized[$name] = reorder_assoc($classInfo, array(
            'type',
            'name',
            'name_len',
            'parent',
            'refcount',
            'ce_flags',
            'default_properties_count',
            'default_static_members_count',
            'default_properties_table',
            'default_static_members_table',
            'function_table',
            'properties_info',
            'constants_table',
            'interfaces',
            'traits',
        ));
    }

    return $normalized;
}

function prepare_dump_for_output(array $dump, $sourcePath)
{
    $prepared = $dump;

    $prepared['filename'] = basename($sourcePath);

    if (isset($prepared['op_array']) && is_array($prepared['op_array'])) {
        $prepared['op_array'] = normalize_op_array_entry($prepared['op_array']);
    }

    if (isset($prepared['function_table']) && is_array($prepared['function_table'])) {
        $prepared['function_table'] = normalize_function_table($prepared['function_table'], $sourcePath);
    }

    if (isset($prepared['class_table']) && is_array($prepared['class_table'])) {
        $prepared['class_table'] = normalize_class_table($prepared['class_table'], $sourcePath);
    }

    return reorder_assoc($prepared, array(
        'filename',
        'op_array',
        'function_table',
        'class_table',
        'ioncube_api_calls',
    ));
}
