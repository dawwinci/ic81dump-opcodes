<?php

/*
 * values.php -- primitive value helpers shared across the dumper.
 *
 * Pure functions only: no extension calls, no I/O. They turn raw PHP values
 * (literals, names, paths) into JSON-safe, self-describing structures and
 * provide small generic array utilities used by both the IR and the
 * TXT-normalization layers.
 */

/**
 * Reorder an associative array so the given keys come first (in order),
 * with any remaining keys appended in their original order. Missing keys
 * are skipped. Used to give op_arrays/opcodes a stable, readable layout.
 */
function reorder_assoc(array $value, array $orderedKeys)
{
    $reordered = array();

    foreach ($orderedKeys as $key) {
        if (array_key_exists($key, $value)) {
            $reordered[$key] = $value[$key];
            unset($value[$key]);
        }
    }

    foreach ($value as $key => $item) {
        $reordered[$key] = $item;
    }

    return $reordered;
}

function normalize_path($path)
{
    if (!is_string($path)) {
        return null;
    }

    $path = str_replace('/', DIRECTORY_SEPARATOR, $path);

    return strtolower($path);
}

function describe_value($value)
{
    if (is_null($value)) {
        return null;
    }

    if (is_bool($value) || is_int($value) || is_float($value) || is_string($value)) {
        return $value;
    }

    if (is_array($value)) {
        $described = array();
        $count = 0;
        foreach ($value as $key => $item) {
            $described[$key] = describe_value($item);
            $count++;
            if ($count >= 20) {
                $described['...'] = 'truncated';
                break;
            }
        }
        return $described;
    }

    if (is_object($value)) {
        return 'object(' . get_class($value) . ')';
    }

    if (is_resource($value)) {
        return 'resource';
    }

    return (string) $value;
}

function is_printable_string($value)
{
    return is_string($value) && preg_match('/\A[\x09\x0A\x0D\x20-\x7E]*\z/', $value);
}

function is_valid_php_variable_name($value)
{
    return is_string($value) && preg_match('/\A[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\z/', $value);
}

/**
 * Describe a string in a JSON-safe way: keep the readable value when it is
 * printable, otherwise expose hex/base64/sha1 so binary payloads survive.
 */
function safe_string($value, $previewLength = 160)
{
    $length = strlen($value);
    $preview = substr($value, 0, $previewLength);

    return array(
        'type' => 'string',
        'length' => $length,
        'printable' => is_printable_string($value),
        'value' => is_printable_string($value) ? $value : null,
        'preview' => is_printable_string($preview) ? $preview : null,
        'hex' => bin2hex($value),
        'base64' => base64_encode($value),
        'sha1' => sha1($value),
    );
}

/**
 * Recursively turn any PHP value into a tagged, JSON-safe structure.
 */
function safe_value($value)
{
    if (is_string($value)) {
        return safe_string($value);
    }
    if (is_null($value)) {
        return array('type' => 'null', 'value' => null);
    }
    if (is_bool($value)) {
        return array('type' => 'bool', 'value' => $value);
    }
    if (is_int($value)) {
        return array('type' => 'int', 'value' => $value);
    }
    if (is_float($value)) {
        return array('type' => 'float', 'value' => $value);
    }
    if (is_array($value)) {
        $items = array();
        foreach ($value as $key => $item) {
            $items[$key] = safe_value($item);
        }
        return array('type' => 'array', 'value' => $items);
    }
    if (is_object($value)) {
        return array('type' => 'object', 'class' => get_class($value), 'value' => null);
    }
    if (is_resource($value)) {
        return array('type' => 'resource', 'resource_type' => get_resource_type($value), 'value' => null);
    }

    return array('type' => gettype($value), 'value' => (string)$value);
}
