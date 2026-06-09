<?php

/*
 * flags.php -- decoders for Zend bitmask/extended-value fields (PHP 8.1).
 *
 * All bit values below are the PHP 8.1 zend_compile.h / zend_types.h values
 * (NOT the PHP 7.x layout, where visibility lived in 0x100/0x200/0x400).
 */

/**
 * PHP 8.1 extended_value semantics, decoded per opcode (zend_compile.h).
 */
function decode_extended_value($opcodeName, $extVal)
{
    if ($extVal === null) {
        return null;
    }

    switch ($opcodeName) {
        case 'ZEND_INCLUDE_OR_EVAL':
            // ZEND_EVAL=1 ZEND_INCLUDE=2 ZEND_INCLUDE_ONCE=4 ZEND_REQUIRE=8 ZEND_REQUIRE_ONCE=16
            $map = array(1 => 'eval', 2 => 'include', 4 => 'include_once', 8 => 'require', 16 => 'require_once');
            return isset($map[$extVal]) ? $map[$extVal] : 'unknown(' . $extVal . ')';

        case 'ZEND_CAST':
            // IS_NULL=1 IS_LONG=4 IS_DOUBLE=5 IS_STRING=6 IS_ARRAY=7 IS_OBJECT=8 _IS_BOOL=13
            $map = array(1 => 'null', 2 => 'false', 3 => 'bool', 4 => 'int', 5 => 'float',
                         6 => 'string', 7 => 'array', 8 => 'object', 13 => 'bool');
            return isset($map[$extVal]) ? $map[$extVal] : 'unknown(' . $extVal . ')';

        case 'ZEND_CATCH':
            // PHP 8.1: extended_value != 0 means this is the last catch in the chain
            return array('is_last_catch' => (bool)$extVal);

        case 'ZEND_FETCH_R':
        case 'ZEND_FETCH_W':
        case 'ZEND_FETCH_RW':
        case 'ZEND_FETCH_FUNC_ARG':
        case 'ZEND_FETCH_UNSET':
        case 'ZEND_FETCH_IS':
            // ZEND_FETCH_TYPE_MASK=0x70000000 ZEND_FETCH_GLOBAL=0 ZEND_FETCH_LOCAL=0x10000000
            $type = $extVal & 0x70000000;
            $typeMap = array(0 => 'global', 0x10000000 => 'local', 0x40000000 => 'global_lock');
            return array(
                'fetch_type' => isset($typeMap[$type]) ? $typeMap[$type] : 'unknown(0x' . dechex($type) . ')',
                'arg'        => $extVal & 0x000fffff,
            );

        default:
            return null;
    }
}

// PHP 8.1 fn_flags bitmask (zend_compile.h):
//   ZEND_ACC_PUBLIC=0x01 PROTECTED=0x02 PRIVATE=0x04
//   ZEND_ACC_STATIC=0x10 FINAL=0x20 ABSTRACT=0x40
//   ZEND_ACC_DEPRECATED=0x40000 CLOSURE=0x100000 GENERATOR=0x800000
//   ZEND_ACC_VARIADIC=0x1000000 RETURN_REFERENCE=0x4000000 HAS_RETURN_TYPE=0x40000000
function decode_fn_flags($flags)
{
    $flags = (int)$flags;
    $vis = 'none';
    if ($flags & 0x01)      $vis = 'public';
    elseif ($flags & 0x02)  $vis = 'protected';
    elseif ($flags & 0x04)  $vis = 'private';

    return array(
        'visibility'        => $vis,
        'is_static'         => (bool)($flags & 0x10),
        'is_abstract'       => (bool)($flags & 0x40),
        'is_final'          => (bool)($flags & 0x20),
        'is_ctor'           => (bool)($flags & 0x2000),
        'is_dtor'           => (bool)($flags & 0x4000),
        'is_deprecated'     => (bool)($flags & 0x40000),
        'is_closure'        => (bool)($flags & 0x100000),
        'is_generator'      => (bool)($flags & 0x800000),
        'is_variadic'       => (bool)($flags & 0x1000000),
        'returns_reference' => (bool)($flags & 0x4000000),
        'has_return_type'   => (bool)($flags & 0x40000000),
    );
}

// PHP 8.1 ce_flags bitmask (zend_compile.h):
//   ZEND_ACC_INTERFACE=0x01 TRAIT=0x02 ANON_CLASS=0x04 LINKED=0x08
//   ZEND_ACC_IMPLICIT_ABSTRACT_CLASS=0x10 FINAL=0x20 EXPLICIT_ABSTRACT_CLASS=0x40
function decode_ce_flags($flags)
{
    $flags = (int)$flags;
    return array(
        'is_interface'         => (bool)($flags & 0x01),
        'is_trait'             => (bool)($flags & 0x02),
        'is_anon'              => (bool)($flags & 0x04),
        'is_linked'            => (bool)($flags & 0x08),
        'is_implicit_abstract' => (bool)($flags & 0x10),
        'is_final'             => (bool)($flags & 0x20),
        'is_abstract'          => (bool)($flags & 0x40),
        'is_explicit_abstract' => (bool)($flags & 0x40),
    );
}

// PHP 8.1 property flags: same visibility bits as fn_flags, plus ZEND_ACC_STATIC=0x10
function decode_property_flags($flags)
{
    $flags = (int)$flags;
    $vis = 'public';
    if ($flags & 0x01)      $vis = 'public';
    elseif ($flags & 0x02)  $vis = 'protected';
    elseif ($flags & 0x04)  $vis = 'private';

    return array(
        'visibility' => $vis,
        'is_static'  => (bool)($flags & 0x10),
    );
}
