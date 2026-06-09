<?php

/*
 * ir.php -- builds the icdump-ir-v1 structure (the JSON output).
 *
 * Turns the normalized raw dump into per-op_array intermediate representation:
 * decoded opcodes with resolved operands/CV names/jump targets, literals, a
 * control-flow graph, and decompile-oriented analysis (call/return/assign
 * sites, literal xrefs, opcode stats). Depends on values.php, flags.php.
 */

function opcode_label($opcode)
{
    if (isset($opcode['resolved_opcode_name']) && $opcode['resolved_opcode_name'] !== '') {
        return $opcode['resolved_opcode_name'];
    }
    if (isset($opcode['opcode_name']) && $opcode['opcode_name'] !== '') {
        return $opcode['opcode_name'];
    }

    if (isset($opcode['resolved_opcode'])) {
        return '#' . $opcode['resolved_opcode'];
    }
    return '#' . (isset($opcode['opcode']) ? $opcode['opcode'] : '?');
}

function opcode_number_from_name($opcodeName)
{
    static $map = array(
        'ZEND_JMP' => 42,
        'ZEND_JMPZ' => 43,
        'ZEND_JMPNZ' => 44,
        'ZEND_JMPZNZ' => 45,
        'ZEND_JMPZ_EX' => 46,
        'ZEND_JMPNZ_EX' => 47,
        'ZEND_FE_FETCH_R' => 78,
        'ZEND_FE_FETCH_RW' => 126,
        'ZEND_JMP_SET' => 152,
    );

    return isset($map[$opcodeName]) ? $map[$opcodeName] : null;
}

function literal_ir($literal, $index)
{
    $safe = safe_value($literal);
    $safe['index'] = $index;
    return reorder_assoc($safe, array(
        'index',
        'type',
        'length',
        'printable',
        'value',
        'preview',
        'hex',
        'base64',
        'sha1',
    ));
}

function operand_ir(array $opcode, $prefix, array $cvNames = array())
{
    $typeKey = $prefix . '_type';
    $typeNameKey = $prefix . '_type_name';
    $literalKey = $prefix . '.literal';
    $cvNameKey = $prefix . '.cv_name';
    $constantKey = $prefix . '.constant';
    $varKey = $prefix . '.var';
    $numKey = $prefix . '.num';
    $oplineKey = $prefix . '.opline_num';

    $operand = array(
        'type' => isset($opcode[$typeKey]) ? $opcode[$typeKey] : null,
        'type_name' => isset($opcode[$typeNameKey]) ? $opcode[$typeNameKey] : null,
        'constant' => isset($opcode[$constantKey]) ? $opcode[$constantKey] : null,
        'var' => isset($opcode[$varKey]) ? $opcode[$varKey] : null,
        'num' => isset($opcode[$numKey]) ? $opcode[$numKey] : null,
        'opline_num' => isset($opcode[$oplineKey]) ? $opcode[$oplineKey] : null,
        'cv_name' => isset($opcode[$cvNameKey]) ? $opcode[$cvNameKey] : null,
    );

    if (array_key_exists($literalKey, $opcode)) {
        $operand['literal'] = safe_value($opcode[$literalKey]);
    }

    return apply_clean_cv_name($operand, $cvNames);
}

function cv_index_from_operand(array $operand)
{
    if (!isset($operand['type_name']) || $operand['type_name'] !== 'IS_CV') {
        return null;
    }
    if (!isset($operand['var'])) {
        return null;
    }

    $slot = (int)((int)$operand['var'] / 16);
    $index = $slot - 3;
    return $index >= 0 ? $index : null;
}

function make_clean_cv_name($index, $rawName, array $argInfo)
{
    if (isset($argInfo[$index]['name']) && is_valid_php_variable_name($argInfo[$index]['name'])) {
        return $argInfo[$index]['name'];
    }

    if (is_valid_php_variable_name($rawName) && is_printable_string($rawName)) {
        return $rawName;
    }

    return '_cv' . $index;
}

function build_clean_cv_names(array $opArray, array $argInfo)
{
    $rawVars = isset($opArray['vars']) && is_array($opArray['vars']) ? array_values($opArray['vars']) : array();
    $lastVar = isset($opArray['last_var']) ? (int)$opArray['last_var'] : count($rawVars);
    $count = max($lastVar, count($rawVars), count($argInfo));
    $names = array();

    for ($i = 0; $i < $count; $i++) {
        $rawName = isset($rawVars[$i]) && is_string($rawVars[$i]) ? $rawVars[$i] : null;
        $names[$i] = make_clean_cv_name($i, $rawName, $argInfo);
    }

    return $names;
}

function apply_clean_cv_name(array $operand, array $cvNames)
{
    $index = cv_index_from_operand($operand);
    if ($index === null || !isset($cvNames[$index])) {
        return $operand;
    }

    if (isset($operand['cv_name']) && $operand['cv_name'] !== $cvNames[$index]) {
        $operand['cv_name_raw'] = safe_value($operand['cv_name']);
    }
    $operand['cv_index'] = $index;
    $operand['cv_name'] = $cvNames[$index];
    return $operand;
}

function opcode_jump_targets(array $opcode)
{
    $name = opcode_label($opcode);
    if ($name === 'ZEND_CATCH' &&
        isset($opcode['extended_value']) &&
        (((int)$opcode['extended_value'] & 1) !== 0)) {
        return array();
    }

    if (isset($opcode['jump_targets']) && is_array($opcode['jump_targets'])) {
        return array_values(array_unique(array_filter(array_map('intval', $opcode['jump_targets']), function ($target) {
            return $target >= 0;
        })));
    }

    $targets = array();
    $unresolvedIonCubeJump =
        isset($opcode['handler'], $opcode['lineno'], $opcode['extended_value']) &&
        (int)$opcode['handler'] === 0 &&
        (int)$opcode['lineno'] === 0 &&
        (int)$opcode['extended_value'] === 0 &&
        isset($opcode['op1_type'], $opcode['op2_type'], $opcode['result_type']) &&
        (int)$opcode['op1_type'] === 0 &&
        (int)$opcode['op2_type'] === 0 &&
        (int)$opcode['result_type'] === 0;

    $op1Target = array('ZEND_JMP', 'ZEND_FAST_CALL');
    $op2Target = array(
        'ZEND_JMPZ',
        'ZEND_JMPNZ',
        'ZEND_JMPZNZ',
        'ZEND_JMPZ_EX',
        'ZEND_JMPNZ_EX',
        'ZEND_FE_RESET_R',
        'ZEND_FE_RESET_RW',
        'ZEND_JMP_SET',
        'ZEND_COALESCE',
        'ZEND_ASSERT_CHECK',
        'ZEND_CATCH',
    );

    if (in_array($name, $op1Target, true) && isset($opcode['op1.opline_num'])) {
        $target = (int)$opcode['op1.opline_num'];
        if (!($unresolvedIonCubeJump && $target === 0)) {
            $targets[] = $target;
        }
    }
    if (in_array($name, $op2Target, true) && isset($opcode['op2.opline_num'])) {
        $target = (int)$opcode['op2.opline_num'];
        if (!($unresolvedIonCubeJump && $target === 0)) {
            $targets[] = $target;
        }
    }
    // JMPZNZ second target: non-zero/non-null branch resolved by C extension
    if ($name === 'ZEND_JMPZNZ' && isset($opcode['jmpznz_true_opline']) && (int)$opcode['jmpznz_true_opline'] >= 0) {
        $targets[] = (int)$opcode['jmpznz_true_opline'];
    }
    if (($name === 'ZEND_FE_FETCH_R' || $name === 'ZEND_FE_FETCH_RW')) {
        if (isset($opcode['fe_fetch_done_opline']) && (int)$opcode['fe_fetch_done_opline'] >= 0) {
            $targets[] = (int)$opcode['fe_fetch_done_opline'];
        } elseif (isset($opcode['extended_value']) && isset($opcode['opcode_index'])) {
            $ext = (int)$opcode['extended_value'];
            if ($ext % 28 === 0) {
                $targets[] = (int)$opcode['opcode_index'] + (int)($ext / 28);
            }
        }
    }

    return array_values(array_unique(array_filter($targets, function ($target) {
        return $target >= 0;
    })));
}

function opcode_ir(array $opcode, $index, array $cvNames = array())
{
    $targets    = opcode_jump_targets($opcode);
    $opcodeName = opcode_label($opcode);
    $opcodeNum  = isset($opcode['resolved_opcode']) ? (int)$opcode['resolved_opcode'] : (isset($opcode['opcode']) ? (int)$opcode['opcode'] : null);
    if (($opcodeNum === null || $opcodeNum === 0) && is_string($opcodeName)) {
        $knownOpcodeNum = opcode_number_from_name($opcodeName);
        if ($knownOpcodeNum !== null) {
            $opcodeNum = $knownOpcodeNum;
        }
    }
    $extVal     = isset($opcode['extended_value']) ? $opcode['extended_value'] : null;

    // Mask ionCube-injected bits from lineno (same mask used for line_start/line_end in C ext)
    $linenoRaw = isset($opcode['lineno']) ? (int)$opcode['lineno'] : null;
    $lineno    = $linenoRaw !== null ? ($linenoRaw & ~0x600000) : null;

    $ir = array(
        'index'                  => $index,
        'line'                   => $lineno,
        'lineno_raw'             => $linenoRaw !== $lineno ? $linenoRaw : null,
        'opcode'                 => $opcodeNum,
        'opcode_name'            => $opcodeName,
        'handler'                => isset($opcode['handler']) ? $opcode['handler'] : null,
        'extended_value'         => $extVal,
        'extended_value_decoded' => decode_extended_value($opcodeName, $extVal),
        'op1'                    => operand_ir($opcode, 'op1', $cvNames),
        'op2'                    => operand_ir($opcode, 'op2', $cvNames),
        'result'                 => operand_ir($opcode, 'result', $cvNames),
        'jump_targets'           => $targets,
        'is_call'                => in_array($opcodeName, array('ZEND_INIT_FCALL', 'ZEND_INIT_FCALL_BY_NAME', 'ZEND_DO_FCALL', 'ZEND_DO_FCALL_BY_NAME'), true),
        'is_include_or_eval'     => $opcodeName === 'ZEND_INCLUDE_OR_EVAL',
        'is_lambda_declare'      => $opcodeName === 'ZEND_DECLARE_LAMBDA_FUNCTION',
    );

    if (isset($opcode['opcode']) && $opcodeNum !== null && (int)$opcode['opcode'] !== (int)$opcodeNum) {
        $ir['opcode_display'] = (int)$opcode['opcode'];
    }
    if (isset($opcode['opcode_name']) && $opcode['opcode_name'] !== $opcodeName) {
        $ir['opcode_name_display'] = $opcode['opcode_name'];
    }
    foreach (array('opcode_raw', 'opcode_xor_decoded', 'resolved_opcode_source', 'ic_key_byte', 'ic_key_dword', 'ic_meta_flags', 'ic_operand_flags') as $debugKey) {
        if (isset($opcode[$debugKey])) {
            $ir[$debugKey] = $opcode[$debugKey];
        }
    }

    // JMPZNZ second target from C extension (non-zero/non-null branch)
    if ($opcodeName === 'ZEND_JMPZNZ' && isset($opcode['jmpznz_true_opline'])) {
        $ir['jmpznz_true_opline'] = (int)$opcode['jmpznz_true_opline'];
    }
    if (($opcodeName === 'ZEND_FE_FETCH_R' || $opcodeName === 'ZEND_FE_FETCH_RW') && isset($opcode['fe_fetch_done_opline'])) {
        $ir['fe_fetch_done_opline'] = (int)$opcode['fe_fetch_done_opline'];
    }

    // Propagate decode_failed flag set by C extension on unreadable opcodes
    if (!empty($opcode['decode_failed'])) {
        $ir['decode_failed'] = true;
    }
    if (isset($opcode['resolved_function_name'])) {
        $ir['resolved_function_name'] = $opcode['resolved_function_name'];
        if (in_array($opcodeName, array('ZEND_INIT_FCALL', 'ZEND_INIT_FCALL_BY_NAME', 'ZEND_INIT_NS_FCALL_BY_NAME'), true)) {
            $ir['call_name'] = $opcode['resolved_function_name'];
            if (isset($ir['op2']) && is_array($ir['op2'])) {
                $ir['op2']['resolved_literal'] = safe_value($opcode['resolved_function_name']);
            }
        }
    }
    if (isset($opcode['resolved_function_name_source'])) {
        $ir['resolved_function_name_source'] = $opcode['resolved_function_name_source'];
        if (isset($ir['op2']) && is_array($ir['op2']) && isset($ir['op2']['resolved_literal'])) {
            $ir['op2']['resolved_literal_source'] = $opcode['resolved_function_name_source'];
        }
    }
    if (isset($opcode['resolved_function_type'])) {
        $ir['resolved_function_type'] = $opcode['resolved_function_type'];
    }
    if (isset($opcode['ioncube_api_value_function'])) {
        $ir['ioncube_api_value_function'] = $opcode['ioncube_api_value_function'];
    }
    if (isset($opcode['ioncube_api_value_source'])) {
        $ir['ioncube_api_value_source'] = $opcode['ioncube_api_value_source'];
    }
    if (array_key_exists('ioncube_api_value', $opcode)) {
        $ir['ioncube_api_value'] = safe_value($opcode['ioncube_api_value']);
    }
    if (isset($opcode['ioncube_api_value_error'])) {
        $ir['ioncube_api_value_error'] = $opcode['ioncube_api_value_error'];
    }

    return $ir;
}

function semantic_opcode_number($name)
{
    static $map = array(
        'ZEND_CONCAT' => 8,
        'ZEND_IS_IDENTICAL' => 16,
        'ZEND_IS_NOT_IDENTICAL' => 17,
        'ZEND_ASSIGN' => 22,
    );
    return isset($map[$name]) ? $map[$name] : null;
}

function semantic_obfuscated_operator_name($name)
{
    static $names = array(
        'ZEND_NOP' => true,
        'ZEND_ADD' => true,
        'ZEND_SUB' => true,
        'ZEND_MUL' => true,
        'ZEND_DIV' => true,
        'ZEND_MOD' => true,
        'ZEND_BW_XOR' => true,
        'ZEND_BW_OR' => true,
        'ZEND_BW_AND' => true,
        'ZEND_BW_NOT' => true,
        'ZEND_BOOL_XOR' => true,
        'ZEND_BOOL_NOT' => true,
        'ZEND_SL' => true,
        'ZEND_SR' => true,
        'ZEND_POW' => true,
        'ZEND_IS_EQUAL' => true,
        'ZEND_IS_NOT_EQUAL' => true,
        'ZEND_IS_SMALLER' => true,
        'ZEND_IS_SMALLER_OR_EQUAL' => true,
        'ZEND_IS_IDENTICAL' => true,
        'ZEND_IS_NOT_IDENTICAL' => true,
    );
    return is_string($name) && isset($names[$name]);
}

function semantic_operand_key(array $operand)
{
    foreach (array('var', 'constant', 'num') as $key) {
        if (isset($operand[$key]) && is_numeric($operand[$key])) {
            return (int)$operand[$key];
        }
    }
    return 0;
}

function semantic_literal_value(array $operand)
{
    if (!isset($operand['literal']) || !is_array($operand['literal'])) {
        return null;
    }
    return array_key_exists('value', $operand['literal']) ? $operand['literal']['value'] : null;
}

function semantic_temp_key(array $operand)
{
    $type = isset($operand['type_name']) ? $operand['type_name'] : null;
    if ($type !== 'IS_TMP_VAR' && $type !== 'IS_VAR') {
        return null;
    }
    return semantic_operand_key($operand);
}

function semantic_temp_key_strict(array $operand)
{
    $type = isset($operand['type_name']) ? $operand['type_name'] : null;
    if ($type !== 'IS_TMP_VAR' && $type !== 'IS_VAR') {
        return null;
    }
    foreach (array('var', 'constant', 'num') as $key) {
        if (isset($operand[$key]) && is_numeric($operand[$key])) {
            return (int)$operand[$key];
        }
    }
    return null;
}

function semantic_apply_resolved_opcode(array &$op, $name, $source)
{
    $num = semantic_opcode_number($name);
    if ($num === null) {
        return;
    }
    if (isset($op['opcode_name']) && $op['opcode_name'] !== $name && !isset($op['opcode_name_display'])) {
        $op['opcode_name_display'] = $op['opcode_name'];
    }
    if (isset($op['opcode']) && (int)$op['opcode'] !== $num && !isset($op['opcode_display'])) {
        $op['opcode_display'] = (int)$op['opcode'];
    }
    $op['opcode'] = $num;
    $op['opcode_name'] = $name;
    $op['resolved_opcode_name'] = $name;
    $op['resolved_opcode_source'] = $source;
    $op['extended_value_decoded'] = decode_extended_value($name, isset($op['extended_value']) ? $op['extended_value'] : null);
}

function semantic_apply_resolved_opcode_name(array &$op, $name, $source)
{
    if (isset($op['opcode_name']) && $op['opcode_name'] !== $name && !isset($op['opcode_name_display'])) {
        $op['opcode_name_display'] = $op['opcode_name'];
    }
    $op['opcode_name'] = $name;
    $op['resolved_opcode_name'] = $name;
    $op['resolved_opcode_source'] = $source;
    $op['extended_value_decoded'] = decode_extended_value($name, isset($op['extended_value']) ? $op['extended_value'] : null);
}

function semantic_has_authoritative_opcode_resolution(array $op)
{
    if (!isset($op['resolved_opcode_source'])) {
        return false;
    }
    return in_array($op['resolved_opcode_source'], array(
        'ioncube_materializer_capture',
        'ioncube_loader_handler',
        'zend_vm_handler',
        'zend_op_data_pseudo',
        'ioncube_xor_key',
        'zend_opcode',
    ), true);
}

function semantic_next_meaningful_index(array $ops, $index)
{
    $count = count($ops);
    while ($index < $count) {
        $name = isset($ops[$index]['opcode_name']) ? $ops[$index]['opcode_name'] : null;
        if (!in_array($name, array('ZEND_NOP', 'ZEND_FREE', 'ZEND_FE_FREE'), true)) {
            return $index;
        }
        $index++;
    }
    return null;
}

function semantic_next_branch_consuming_result(array $ops, $index, array $op)
{
    $result = isset($op['result']) && is_array($op['result']) ? $op['result'] : array();
    $resultKey = semantic_temp_key($result);
    if ($resultKey === null) {
        return null;
    }
    $next = semantic_next_meaningful_index($ops, $index + 1);
    if ($next === null) {
        return null;
    }
    $nextName = isset($ops[$next]['opcode_name']) ? $ops[$next]['opcode_name'] : null;
    if ($nextName !== 'ZEND_JMPZ' && $nextName !== 'ZEND_JMPNZ') {
        return null;
    }
    $op1 = isset($ops[$next]['op1']) && is_array($ops[$next]['op1']) ? $ops[$next]['op1'] : array();
    return semantic_operand_key($op1) === $resultKey ? $next : null;
}

function semantic_first_return_literal_in_branch(array $ops, $branchIndex)
{
    if (!isset($ops[$branchIndex]['jump_targets']) || !is_array($ops[$branchIndex]['jump_targets']) || count($ops[$branchIndex]['jump_targets']) === 0) {
        return null;
    }
    $target = (int)$ops[$branchIndex]['jump_targets'][0];
    if ($target <= $branchIndex + 1) {
        return null;
    }
    $limit = min($target, count($ops));
    for ($i = $branchIndex + 1; $i < $limit; $i++) {
        $name = isset($ops[$i]['opcode_name']) ? $ops[$i]['opcode_name'] : null;
        if ($name === 'ZEND_RETURN') {
            $op1 = isset($ops[$i]['op1']) && is_array($ops[$i]['op1']) ? $ops[$i]['op1'] : array();
            return semantic_literal_value($op1);
        }
        if (in_array($name, array('ZEND_JMP', 'ZEND_JMPZ', 'ZEND_JMPNZ', 'ZEND_FE_RESET_R', 'ZEND_FE_FETCH_R'), true)) {
            break;
        }
    }
    return null;
}

function semantic_resolve_branch_compare(array $ops, $index, array $op)
{
    $branch = semantic_next_branch_consuming_result($ops, $index, $op);
    if ($branch === null) {
        return null;
    }
    $op2 = isset($op['op2']) && is_array($op['op2']) ? $op['op2'] : array();
    $literal = semantic_literal_value($op2);
    if (is_bool($literal)) {
        return 'ZEND_IS_IDENTICAL';
    }
    if (is_string($literal)) {
        $returned = semantic_first_return_literal_in_branch($ops, $branch);
        if ($returned === 'invalid' && $literal !== '' && $literal !== 'invalid') {
            return 'ZEND_IS_NOT_IDENTICAL';
        }
        return 'ZEND_IS_IDENTICAL';
    }
    return null;
}

function semantic_operand_is_stringish(array $operand, array $stringishTemps)
{
    $literal = semantic_literal_value($operand);
    if (is_string($literal)) {
        return true;
    }
    $key = semantic_temp_key($operand);
    return $key !== null && !empty($stringishTemps[$key]);
}

function semantic_is_structural_inherited_declare(array $op, array $classFetchTemps)
{
    if (!isset($op['opcode']) || (int)$op['opcode'] !== 201) {
        return false;
    }
    $name = isset($op['opcode_name']) ? $op['opcode_name'] : null;
    if ($name !== '#201') {
        return false;
    }
    $op1 = isset($op['op1']) && is_array($op['op1']) ? $op['op1'] : array();
    $op2 = isset($op['op2']) && is_array($op['op2']) ? $op['op2'] : array();
    $result = isset($op['result']) && is_array($op['result']) ? $op['result'] : array();
    if (($op1['type_name'] ?? null) !== 'IS_CONST' || !is_string(semantic_literal_value($op1))) {
        return false;
    }
    if (semantic_temp_key_strict($result) === null) {
        return false;
    }
    $parentKey = semantic_temp_key_strict($op2);
    return $parentKey !== null && isset($classFetchTemps[$parentKey]);
}

function resolve_semantic_opcodes(array &$ops)
{
    if (getenv('OPCODEDUMP_DISABLE_SEMANTIC_OPCODE_RESOLVE')) {
        return;
    }
    $stringishTemps = array();
    $classFetchTemps = array();
    $count = count($ops);

    for ($i = 0; $i < $count; $i++) {
        if (!isset($ops[$i]) || !is_array($ops[$i])) {
            continue;
        }
        $name = isset($ops[$i]['opcode_name']) ? $ops[$i]['opcode_name'] : null;
        $op1 = isset($ops[$i]['op1']) && is_array($ops[$i]['op1']) ? $ops[$i]['op1'] : array();
        $op2 = isset($ops[$i]['op2']) && is_array($ops[$i]['op2']) ? $ops[$i]['op2'] : array();
        $result = isset($ops[$i]['result']) && is_array($ops[$i]['result']) ? $ops[$i]['result'] : array();

        if ($name === 'ZEND_FETCH_CLASS') {
            $literal = semantic_literal_value($op2);
            $key = semantic_temp_key_strict($result);
            if ($key !== null && is_string($literal) && $literal !== '') {
                $classFetchTemps[$key] = $literal;
            }
            continue;
        }

        if (semantic_is_structural_inherited_declare($ops[$i], $classFetchTemps)) {
            semantic_apply_resolved_opcode_name($ops[$i], 'ZEND_DECLARE_INHERITED_CLASS_DELAYED', 'opcodedump_structural_class_declare');
            continue;
        }

        if ($name === 'ZEND_FETCH_CONSTANT') {
            $literal = semantic_literal_value($op2);
            $key = semantic_temp_key($result);
            if ($key !== null && is_string($literal) && strpos($literal, 'DIR_') === 0) {
                $stringishTemps[$key] = true;
            }
            continue;
        }

        if (semantic_has_authoritative_opcode_resolution($ops[$i])) {
            continue;
        }

        if (!semantic_obfuscated_operator_name($name)) {
            continue;
        }

        if (($op1['type_name'] ?? null) === 'IS_CV' &&
            ($op2['type_name'] ?? null) !== 'IS_UNUSED' &&
            ($result['type_name'] ?? null) === 'IS_UNUSED') {
            semantic_apply_resolved_opcode($ops[$i], 'ZEND_ASSIGN', 'opcodedump_semantic_context');
            continue;
        }

        $compare = semantic_resolve_branch_compare($ops, $i, $ops[$i]);
        if ($compare !== null) {
            semantic_apply_resolved_opcode($ops[$i], $compare, 'opcodedump_semantic_context');
            continue;
        }

        if (semantic_next_branch_consuming_result($ops, $i, $ops[$i]) === null &&
            ($result['type_name'] ?? null) !== 'IS_UNUSED' &&
            (semantic_operand_is_stringish($op1, $stringishTemps) || semantic_operand_is_stringish($op2, $stringishTemps))) {
            semantic_apply_resolved_opcode($ops[$i], 'ZEND_CONCAT', 'opcodedump_semantic_context');
            $key = semantic_temp_key($result);
            if ($key !== null) {
                $stringishTemps[$key] = true;
            }
        }
    }
}

function opcode_falls_through($opcodeName)
{
    return !in_array($opcodeName, array(
        'ZEND_JMP',
        'ZEND_RETURN',
        'ZEND_THROW',
        'ZEND_EXIT',
    ), true);
}

function build_cfg(array $opcodes)
{
    $count = count($opcodes);
    if ($count === 0) {
        return array('blocks' => array(), 'edges' => array());
    }

    $leaders = array(0 => true);
    foreach ($opcodes as $index => $opcode) {
        foreach (opcode_jump_targets($opcode) as $target) {
            if ($target >= 0 && $target < $count) {
                $leaders[$target] = true;
            }
        }
        if (!empty(opcode_jump_targets($opcode)) && $index + 1 < $count) {
            $leaders[$index + 1] = true;
        }
    }

    $leaderList = array_keys($leaders);
    sort($leaderList, SORT_NUMERIC);

    $blocks = array();
    $opToBlock = array();
    foreach ($leaderList as $blockIndex => $start) {
        $end = ($blockIndex + 1 < count($leaderList)) ? $leaderList[$blockIndex + 1] - 1 : $count - 1;
        $id = 'B' . $blockIndex;
        $blocks[] = array(
            'id' => $id,
            'start' => $start,
            'end' => $end,
        );
        for ($i = $start; $i <= $end; $i++) {
            $opToBlock[$i] = $id;
        }
    }

    $edges = array();
    foreach ($blocks as $block) {
        $lastIndex = $block['end'];
        $lastOpcode = isset($opcodes[$lastIndex]) && is_array($opcodes[$lastIndex]) ? $opcodes[$lastIndex] : array();
        $lastName = opcode_label($lastOpcode);

        foreach (opcode_jump_targets($lastOpcode) as $target) {
            if (isset($opToBlock[$target])) {
                $edges[] = array('from' => $block['id'], 'to' => $opToBlock[$target], 'kind' => 'jump');
            }
        }

        if (opcode_falls_through($lastName) && $lastIndex + 1 < $count && isset($opToBlock[$lastIndex + 1])) {
            $edges[] = array('from' => $block['id'], 'to' => $opToBlock[$lastIndex + 1], 'kind' => 'fallthrough');
        }
    }

    return array('blocks' => $blocks, 'edges' => $edges);
}

function build_opcode_stats(array $opcodes)
{
    $stats = array();
    foreach ($opcodes as $opcode) {
        if (!is_array($opcode)) {
            continue;
        }
        $label = opcode_label($opcode);
        if (!isset($stats[$label])) {
            $stats[$label] = 0;
        }
        $stats[$label]++;
    }
    ksort($stats);
    return $stats;
}

function build_literal_xrefs(array $opcodes)
{
    $xrefs = array();
    foreach ($opcodes as $index => $opcode) {
        if (!is_array($opcode)) {
            continue;
        }
        foreach (array('op1', 'op2', 'result') as $operand) {
            if (!isset($opcode[$operand]) || !is_array($opcode[$operand])) {
                continue;
            }
            $op = $opcode[$operand];
            if (!isset($op['constant']) || !isset($op['literal']) || !is_array($op['literal'])) {
                continue;
            }
            $literalIndex = (int)$op['constant'];
            if (!isset($xrefs[$literalIndex])) {
                $xrefs[$literalIndex] = array();
            }
            $xrefs[$literalIndex][] = array(
                'opcode_index' => $index,
                'opcode_name' => opcode_label($opcode),
                'operand' => $operand,
            );
        }
    }
    ksort($xrefs);
    return $xrefs;
}

function decompile_site_operand(array $opcode, $prefix)
{
    if (isset($opcode[$prefix]) && is_array($opcode[$prefix])) {
        return $opcode[$prefix];
    }
    return operand_ir($opcode, $prefix);
}

function build_decompile_sites(array $opcodes)
{
    $sites = array(
        'calls' => array(),
        'include_eval' => array(),
        'lambda_declarations' => array(),
        'assignments' => array(),
        'returns' => array(),
    );

    foreach ($opcodes as $index => $opcode) {
        if (!is_array($opcode)) {
            continue;
        }
        $label = opcode_label($opcode);
        $entry = array(
            'opcode_index' => isset($opcode['index']) ? $opcode['index'] : $index,
            'opcode_name' => $label,
            'line' => isset($opcode['line']) ? $opcode['line'] : (isset($opcode['lineno']) ? $opcode['lineno'] : null),
        );

        if (in_array($label, array('ZEND_INIT_FCALL', 'ZEND_INIT_FCALL_BY_NAME', 'ZEND_DO_FCALL', 'ZEND_DO_FCALL_BY_NAME'), true)) {
            $entry['op1'] = decompile_site_operand($opcode, 'op1');
            $entry['op2'] = decompile_site_operand($opcode, 'op2');
            $sites['calls'][] = $entry;
        } elseif ($label === 'ZEND_INCLUDE_OR_EVAL') {
            $entry['op1'] = decompile_site_operand($opcode, 'op1');
            $entry['extended_value'] = isset($opcode['extended_value']) ? $opcode['extended_value'] : null;
            $sites['include_eval'][] = $entry;
        } elseif ($label === 'ZEND_DECLARE_LAMBDA_FUNCTION') {
            $entry['op1'] = decompile_site_operand($opcode, 'op1');
            $entry['result'] = decompile_site_operand($opcode, 'result');
            $sites['lambda_declarations'][] = $entry;
        } elseif (strpos($label, 'ZEND_ASSIGN') === 0) {
            $entry['op1'] = decompile_site_operand($opcode, 'op1');
            $entry['op2'] = decompile_site_operand($opcode, 'op2');
            $entry['result'] = decompile_site_operand($opcode, 'result');
            $sites['assignments'][] = $entry;
        } elseif ($label === 'ZEND_RETURN') {
            $entry['op1'] = decompile_site_operand($opcode, 'op1');
            $sites['returns'][] = $entry;
        }
    }

    return $sites;
}

function arg_info_ir($argInfoArray, $numArgs, $requiredNumArgs)
{
    if (!is_array($argInfoArray) || empty($argInfoArray)) {
        return array();
    }

    // PHP 8.1 type codes from zend_types.h
    $typeCodes = array(
        1 => 'null', 2 => 'false', 3 => 'bool', 4 => 'int',
        5 => 'float', 6 => 'string', 7 => 'array', 8 => 'object', 13 => 'bool',
    );

    $result = array();
    foreach ($argInfoArray as $index => $argInfo) {
        if (!is_array($argInfo)) {
            continue;
        }

        $name      = isset($argInfo['name']) && is_string($argInfo['name']) ? $argInfo['name'] : null;
        $className = isset($argInfo['class_name']) && is_string($argInfo['class_name']) && $argInfo['class_name'] !== ''
            ? $argInfo['class_name'] : null;
        $typeCode  = isset($argInfo['type']) ? (int)$argInfo['type'] : 0;
        $typeName  = $className !== null
            ? $className
            : (isset($typeCodes[$typeCode]) ? $typeCodes[$typeCode] : ($typeCode > 0 ? 'type(' . $typeCode . ')' : null));

        $hasDefault = $numArgs !== null && $requiredNumArgs !== null
            ? ((int)$index >= (int)$requiredNumArgs)
            : null;

        $result[] = array(
            'index'             => (int)$index,
            'name'              => $name,
            'type_name'         => $typeName,
            'class_name'        => $className,
            'type_code'         => $typeCode,
            'pass_by_reference' => isset($argInfo['pass_by_reference']) ? (bool)$argInfo['pass_by_reference'] : false,
            'allow_null'        => isset($argInfo['allow_null'])        ? (bool)$argInfo['allow_null']        : false,
            'is_variadic'       => isset($argInfo['is_variadic'])       ? (bool)$argInfo['is_variadic']       : false,
            'has_default'       => $hasDefault,
        );
    }
    return $result;
}

// Decode return type from arg_info[-1] (extracted by C extension as return_type_info)
function return_type_ir($rawReturnType)
{
    if (!is_array($rawReturnType)) {
        return null;
    }

    $typeCodes = array(
        1 => 'null', 2 => 'false', 3 => 'bool', 4 => 'int',
        5 => 'float', 6 => 'string', 7 => 'array', 8 => 'object', 13 => 'bool',
    );

    $className = isset($rawReturnType['class_name']) && is_string($rawReturnType['class_name']) && $rawReturnType['class_name'] !== ''
        ? $rawReturnType['class_name'] : null;
    $typeCode  = isset($rawReturnType['type']) ? (int)$rawReturnType['type'] : 0;
    $typeName  = $className !== null
        ? $className
        : (isset($typeCodes[$typeCode]) ? $typeCodes[$typeCode] : ($typeCode > 0 ? 'type(' . $typeCode . ')' : null));

    return array(
        'type_name'  => $typeName,
        'class_name' => $className,
        'type_code'  => $typeCode,
        'allow_null' => isset($rawReturnType['allow_null']) ? (bool)$rawReturnType['allow_null'] : false,
    );
}

function live_range_ir($liveRangeArray)
{
    $result = array();
    foreach ($liveRangeArray as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $result[] = array(
            'var'   => isset($entry['var'])   ? $entry['var']   : null,
            'start' => isset($entry['start']) ? $entry['start'] : null,
            'end'   => isset($entry['end'])   ? $entry['end']   : null,
        );
    }
    return $result;
}

function try_catch_ir(array $tryCatchArray)
{
    $result = array();
    foreach ($tryCatchArray as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $result[] = array(
            'try_op'     => isset($entry['try_op'])     ? $entry['try_op']     : null,
            'catch_op'   => isset($entry['catch_op'])   ? $entry['catch_op']   : null,
            'finally_op' => isset($entry['finally_op']) ? $entry['finally_op'] : null,
            'finally_end'=> isset($entry['finally_end'])? $entry['finally_end']: null,
        );
    }
    return $result;
}

function op_array_ir($id, $kind, array $opArray, array $meta = array())
{
    $literals = isset($opArray['literals']) && is_array($opArray['literals']) ? $opArray['literals'] : array();
    $opcodes  = isset($opArray['opcodes'])  && is_array($opArray['opcodes'])  ? $opArray['opcodes']  : array();
    $literalIr = array();
    $opcodeIr  = array();
    $fnFlags         = isset($opArray['fn_flags'])         ? (int)$opArray['fn_flags']         : null;
    $numArgs         = isset($opArray['num_args'])         ? (int)$opArray['num_args']         : null;
    $requiredNumArgs = isset($opArray['required_num_args'])? (int)$opArray['required_num_args'] : null;
    $rawArgInfo      = isset($opArray['arg_info']) && is_array($opArray['arg_info']) ? $opArray['arg_info'] : null;
    $rawReturnType   = isset($opArray['return_type_info']) && is_array($opArray['return_type_info']) ? $opArray['return_type_info'] : null;
    $argInfoIr       = arg_info_ir($rawArgInfo, $numArgs, $requiredNumArgs);
    $cleanCvNames    = build_clean_cv_names($opArray, $argInfoIr);

    foreach ($literals as $index => $literal) {
        $literalIr[] = literal_ir($literal, $index);
    }
    foreach ($opcodes as $index => $opcode) {
        if (is_array($opcode)) {
            $opcodeIr[] = opcode_ir($opcode, $index, $cleanCvNames);
        }
    }
    resolve_semantic_opcodes($opcodeIr);

    $tryCatch  = isset($opArray['try_catch_array']) && is_array($opArray['try_catch_array'])
        ? try_catch_ir($opArray['try_catch_array']) : array();
    $liveRange = isset($opArray['live_range']) && is_array($opArray['live_range'])
        ? live_range_ir($opArray['live_range']) : array();

    return array(
        'id'                 => $id,
        'kind'               => $kind,
        'meta'               => $meta,
        'function_name'      => isset($opArray['function_name']) ? safe_value($opArray['function_name']) : safe_value(null),
        'filename'           => isset($opArray['filename'])      ? safe_value($opArray['filename'])      : safe_value(null),
        'scope'              => isset($opArray['scope'])         ? safe_value($opArray['scope'])         : safe_value(null),
        'line_start'         => isset($opArray['line_start'])    ? $opArray['line_start']                : null,
        'line_end'           => isset($opArray['line_end'])      ? $opArray['line_end']                  : null,
        'fn_flags'           => $fnFlags,
        'fn_flags_decoded'   => $fnFlags !== null ? decode_fn_flags($fnFlags) : null,
        'num_args'           => $numArgs,
        'required_num_args'  => $requiredNumArgs,
        'arg_info'           => $argInfoIr,
        'return_type_info'   => return_type_ir($rawReturnType),
        'doc_comment'        => isset($opArray['doc_comment']) ? safe_value($opArray['doc_comment']) : safe_value(null),
        'vars'               => safe_value($cleanCvNames),
        'vars_raw'           => isset($opArray['vars'])        ? safe_value($opArray['vars'])        : safe_value(null),
        'last_var'           => isset($opArray['last_var'])    ? $opArray['last_var']                : null,
        'T'                  => isset($opArray['T'])           ? $opArray['T']                       : null,
        'static_variables'   => isset($opArray['static_variables']) && is_array($opArray['static_variables'])
            ? safe_value($opArray['static_variables']) : safe_value(null),
        'try_catch'          => $tryCatch,
        'live_range'         => $liveRange,
        'literals'           => $literalIr,
        'opcodes'            => $opcodeIr,
        'cfg'                => build_cfg($opcodeIr),
        'analysis'           => array(
            'opcode_stats'   => build_opcode_stats($opcodeIr),
            'literal_xrefs'  => build_literal_xrefs($opcodeIr),
            'sites'          => build_decompile_sites($opcodeIr),
        ),
        'closure_report'     => isset($opArray['closure_report']) ? $opArray['closure_report'] : array(),
    );
}

function add_ir_op_array(array &$ir, $id, $kind, array $opArray, array $meta = array())
{
    if (isset($ir['op_arrays'][$id])) {
        return;
    }

    $ir['op_arrays'][$id] = op_array_ir($id, $kind, $opArray, $meta);
}

function build_decompile_ir($sourcePath, array $dump)
{
    $ir = array(
        'format' => 'icdump-ir-v1',
        'source_file' => $sourcePath,
        'summary' => array(
            'op_array_count' => 0,
            'function_count' => 0,
            'closure_count' => 0,
            'class_count' => isset($dump['class_table']) && is_array($dump['class_table']) ? count($dump['class_table']) : 0,
        ),
        'entry' => 'main',
        'op_arrays' => array(),
        'function_index' => array(),
        'closure_index' => array(),
        'class_index' => array(),
        'ioncube_api_calls' => isset($dump['ioncube_api_calls']) && is_array($dump['ioncube_api_calls'])
            ? safe_value($dump['ioncube_api_calls']) : array('type' => 'array', 'value' => array()),
    );

    if (isset($dump['op_array']) && is_array($dump['op_array'])) {
        add_ir_op_array($ir, 'main', 'main', $dump['op_array']);

        if (isset($dump['op_array']['closures']) && is_array($dump['op_array']['closures'])) {
            foreach ($dump['op_array']['closures'] as $closure) {
                if (!is_array($closure) || !isset($closure['op_array']) || !is_array($closure['op_array'])) {
                    continue;
                }
                $lambdaHex = isset($closure['lambda_id_hex']) ? $closure['lambda_id_hex'] : sha1(serialize($closure));
                $id = 'closure:' . $lambdaHex;
                add_ir_op_array($ir, $id, 'closure', $closure['op_array'], array(
                    'lambda_id' => isset($closure['lambda_id']) ? safe_value($closure['lambda_id']) : safe_value(null),
                    'lambda_id_hex' => $lambdaHex,
                    'literal_index' => isset($closure['literal_index']) ? $closure['literal_index'] : null,
                    'opcode_index' => isset($closure['opcode_index']) ? $closure['opcode_index'] : null,
                    'parent' => 'main',
                ));
                $ir['closure_index'][$lambdaHex] = $id;
            }
        }
    }

    if (isset($dump['function_table']) && is_array($dump['function_table'])) {
        foreach ($dump['function_table'] as $name => $entry) {
            if (!is_array($entry) || !isset($entry['op_array']) || !is_array($entry['op_array'])) {
                continue;
            }
            $keyHex = isset($entry['function_table_key_hex']) ? $entry['function_table_key_hex'] : bin2hex((string)$name);
            $isClosure = isset($entry['function_table_key']) && is_string($entry['function_table_key']) && strpos($entry['function_table_key'], '{closure}') !== false;
            $id = ($isClosure ? 'closure:' : 'function:') . $keyHex;
            add_ir_op_array($ir, $id, $isClosure ? 'closure' : 'function', $entry['op_array'], array(
                'function_table_key' => isset($entry['function_table_key']) ? safe_value($entry['function_table_key']) : safe_value($name),
                'function_table_key_hex' => $keyHex,
            ));
            if ($isClosure) {
                $ir['closure_index'][$keyHex] = $id;
            } else {
                $ir['function_index'][$keyHex] = $id;
            }
        }
    }

    if (isset($dump['class_table']) && is_array($dump['class_table'])) {
        foreach ($dump['class_table'] as $className => $classInfo) {
            $classId  = 'class:' . bin2hex((string)$className);
            $ceFlags  = isset($classInfo['ce_flags']) ? (int)$classInfo['ce_flags'] : null;

            // Build properties_info with flags_decoded + default_value (now from C extension directly)
            $propertiesInfo = array();
            if (isset($classInfo['properties_info']) && is_array($classInfo['properties_info'])) {
                foreach ($classInfo['properties_info'] as $propName => $propInfo) {
                    if (!is_array($propInfo)) {
                        $propertiesInfo[(string)$propName] = safe_value($propInfo);
                        continue;
                    }
                    $propFlags = isset($propInfo['flags']) ? (int)$propInfo['flags'] : null;
                    $propertiesInfo[(string)$propName] = array(
                        'name'              => isset($propInfo['name'])            ? safe_value($propInfo['name'])            : safe_value(null),
                        'flags'             => $propFlags,
                        'flags_decoded'     => $propFlags !== null ? decode_property_flags($propFlags) : null,
                        'offset'            => isset($propInfo['offset'])          ? $propInfo['offset']                      : null,
                        'doc_comment'       => isset($propInfo['doc_comment'])     ? safe_value($propInfo['doc_comment'])     : safe_value(null),
                        'class_name'        => isset($propInfo['class_name'])      ? safe_value($propInfo['class_name'])      : safe_value(null),
                        // default_value now comes directly from C (fixed bug where prop was computed but unused)
                        'has_default_value' => !empty($propInfo['has_default_value']),
                        'default_value'     => array_key_exists('default_value', $propInfo)
                            ? safe_value($propInfo['default_value']) : null,
                    );
                }
            }

            // Build properties_merged: join properties_info + default values from the right table.
            // Instance props are indexed positionally in default_properties_table sorted by offset.
            // Static props use offset as direct index into default_static_members_table.
            $propertiesMerged = array();
            $defaultInstTable  = isset($classInfo['default_properties_table'])     && is_array($classInfo['default_properties_table'])     ? $classInfo['default_properties_table']     : array();
            $defaultStatTable  = isset($classInfo['default_static_members_table']) && is_array($classInfo['default_static_members_table']) ? $classInfo['default_static_members_table'] : array();

            // Separate instance/static, sort instance by offset to get positional index
            $instanceProps = array();
            $staticProps   = array();
            foreach ($propertiesInfo as $propName => $propData) {
                $isStatic = isset($propData['flags_decoded']) && !empty($propData['flags_decoded']['is_static']);
                if ($isStatic) {
                    $staticProps[$propName] = $propData;
                } else {
                    $instanceProps[$propName] = $propData;
                }
            }
            uasort($instanceProps, function ($a, $b) {
                $oa = isset($a['offset']) ? (int)$a['offset'] : 0;
                $ob = isset($b['offset']) ? (int)$b['offset'] : 0;
                return $oa - $ob;
            });

            $instIdx = 0;
            foreach ($instanceProps as $propName => $propData) {
                $hasDefault = array_key_exists($instIdx, $defaultInstTable);
                $defaultVal = $hasDefault ? safe_value($defaultInstTable[$instIdx]) : null;
                $propertiesMerged[$propName] = array(
                    'name'          => $propName,
                    'flags'         => $propData['flags'],
                    'flags_decoded' => $propData['flags_decoded'],
                    'offset'        => isset($propData['offset']) ? $propData['offset'] : null,
                    'has_default_value' => $hasDefault,
                    'default_value' => $defaultVal,
                    'is_static'     => false,
                    'doc_comment'   => isset($propData['doc_comment']) ? $propData['doc_comment'] : null,
                );
                $instIdx++;
            }
            foreach ($staticProps as $propName => $propData) {
                $offset     = isset($propData['offset']) ? (int)$propData['offset'] : -1;
                $hasDefault = ($offset >= 0 && array_key_exists($offset, $defaultStatTable));
                $defaultVal = $hasDefault ? safe_value($defaultStatTable[$offset]) : null;
                $propertiesMerged[$propName] = array(
                    'name'          => $propName,
                    'flags'         => $propData['flags'],
                    'flags_decoded' => $propData['flags_decoded'],
                    'offset'        => isset($propData['offset']) ? $propData['offset'] : null,
                    'has_default_value' => $hasDefault,
                    'default_value' => $defaultVal,
                    'is_static'     => true,
                    'doc_comment'   => isset($propData['doc_comment']) ? $propData['doc_comment'] : null,
                );
            }

            // Build constants_table with safe_value per constant value
            $constantsTable = array();
            if (isset($classInfo['constants_table']) && is_array($classInfo['constants_table'])) {
                foreach ($classInfo['constants_table'] as $constName => $constInfo) {
                    if (!is_array($constInfo)) {
                        $constantsTable[(string)$constName] = safe_value($constInfo);
                        continue;
                    }
                    $constantsTable[(string)$constName] = array(
                        'value'       => array_key_exists('value', $constInfo) ? safe_value($constInfo['value']) : null,
                        'doc_comment' => isset($constInfo['doc_comment']) ? safe_value($constInfo['doc_comment']) : safe_value(null),
                        'ce'          => isset($constInfo['ce'])          ? safe_value($constInfo['ce'])          : safe_value(null),
                    );
                }
            }

            $ir['class_index'][$classId] = array(
                'name'                         => safe_value($className),
                'ce_flags'                     => $ceFlags,
                'ce_flags_decoded'             => $ceFlags !== null ? decode_ce_flags($ceFlags) : null,
                'default_properties_count'      => isset($classInfo['default_properties_count']) ? (int)$classInfo['default_properties_count'] : null,
                'default_static_members_count'  => isset($classInfo['default_static_members_count']) ? (int)$classInfo['default_static_members_count'] : null,
                'default_properties_table_addr' => isset($classInfo['default_properties_table_addr']) ? (int)$classInfo['default_properties_table_addr'] : null,
                'default_static_members_table_addr' => isset($classInfo['default_static_members_table_addr']) ? (int)$classInfo['default_static_members_table_addr'] : null,
                'parent'                       => isset($classInfo['parent'])     ? safe_value($classInfo['parent'])     : safe_value(null),
                'interfaces'                   => isset($classInfo['interfaces']) && is_array($classInfo['interfaces']) ? array_values($classInfo['interfaces']) : array(),
                'traits'                       => isset($classInfo['traits'])     && is_array($classInfo['traits'])     ? array_values($classInfo['traits'])     : array(),
                'properties_info'              => $propertiesInfo,
                'properties_merged'            => $propertiesMerged,
                'constants_table'              => $constantsTable,
                'default_properties_table'     => $defaultInstTable  ? safe_value($defaultInstTable)  : null,
                'default_static_members_table' => $defaultStatTable  ? safe_value($defaultStatTable)  : null,
                'methods'                      => array(),
            );

            if (isset($classInfo['function_table']) && is_array($classInfo['function_table'])) {
                foreach ($classInfo['function_table'] as $methodName => $entry) {
                    if (!is_array($entry) || !isset($entry['op_array']) || !is_array($entry['op_array'])) {
                        continue;
                    }
                    $methodId = $classId . ':method:' . bin2hex((string)$methodName);
                    add_ir_op_array($ir, $methodId, 'method', $entry['op_array'], array(
                        'class'       => $classId,
                        'method_name' => safe_value($methodName),
                    ));
                    $ir['class_index'][$classId]['methods'][(string)$methodName] = $methodId;
                }
            }
        }
    }


    $ir['summary']['op_array_count'] = count($ir['op_arrays']);
    $ir['summary']['function_count'] = count($ir['function_index']);
    $ir['summary']['closure_count'] = count($ir['closure_index']);

    return $ir;
}
