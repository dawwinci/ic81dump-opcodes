<?php

/*
 * stub.php -- dumper-internal scaffolding used to coax ionCube into decoding.
 *
 * ionCube decodes integer literals lazily, in place, the first time the opline
 * that uses them executes. The optional stub-invoke pass (OPCODEDUMP_STUB_INVOKE)
 * instantiates the encoded classes with a permissive mock standing in for the
 * OpenCart registry / db / config / load / session / request services and calls
 * their methods; the runtime snapshot then sees the decoded literal pool.
 *
 * Any class this file fabricates (the stub itself + autoload placeholders) is
 * recorded as "synthetic" so the output layer can exclude it from the dump --
 * those classes belong to the dumper, not to the file being analysed.
 */

/**
 * Record a class name the dumper fabricated so it can be filtered from output.
 */
function opcodedump_register_synthetic_class($name)
{
    if (!is_string($name) || $name === '') {
        return;
    }
    $key = strtolower(ltrim($name, '\\'));
    $GLOBALS['__opcodedump_synthetic_classes'][$key] = true;
}

/**
 * True when $name is a class the dumper itself created (stub / autoload mock),
 * not a class defined by the file under analysis.
 */
function opcodedump_is_synthetic_class($name)
{
    if (!is_string($name)) {
        return false;
    }
    $key = strtolower(ltrim($name, '\\'));
    if ($key === '__opcodedumpstub') {
        return true;
    }
    return isset($GLOBALS['__opcodedump_synthetic_classes'][$key]);
}

/*
 * Universal stub object used by the optional stub-invoke pass.
 *
 * It must survive every access shape the protected code throws at it:
 *  - property reads  ($this->db, $result->num_rows, ...)
 *  - method calls    ($this->db->query(...), $this->config->get(...), ...)
 *  - array access    ($result->row["id"], $this->session->data["currency"])
 *  - iteration       (foreach ($result->rows as $row))
 *  - string/number casts
 */
if (!class_exists('__OpcodedumpStub', false)) {
    class __OpcodedumpStub implements ArrayAccess, Countable, IteratorAggregate
    {
        public function __construct() {}
        public function __get($name)
        {
            // A query-result-like object must look non-empty so that guards
            // such as `if ($result->num_rows)` enter their body and the
            // literals inside get a chance to decode.
            if ($name === 'num_rows' || $name === 'total_rows') {
                return 1;
            }
            if ($name === 'rows') {
                return array(new __OpcodedumpStub());
            }
            if ($name === 'row' || $name === 'data' || $name === 'server'
                || $name === 'get' || $name === 'post' || $name === 'request'
                || $name === 'cookie' || $name === 'files') {
                return array();
            }
            return new __OpcodedumpStub();
        }
        public function __set($name, $value) {}
        public function __isset($name) { return true; }
        public function __unset($name) {}
        public function __call($method, $args) { return new __OpcodedumpStub(); }
        public static function __callStatic($method, $args) { return new __OpcodedumpStub(); }
        public function __invoke() { return new __OpcodedumpStub(); }
        #[\ReturnTypeWillChange]
        public function offsetExists($offset) { return false; }
        #[\ReturnTypeWillChange]
        public function offsetGet($offset) { return null; }
        #[\ReturnTypeWillChange]
        public function offsetSet($offset, $value) {}
        #[\ReturnTypeWillChange]
        public function offsetUnset($offset) {}
        #[\ReturnTypeWillChange]
        public function count() { return 0; }
        #[\ReturnTypeWillChange]
        public function getIterator() { return new ArrayIterator(array()); }
        public function __toString() { return ''; }
    }
}

/**
 * Register an autoloader that fabricates empty (optionally stub-backed) classes
 * for any type the protected code references but never defines. Every fabricated
 * class is tracked as synthetic so it does not pollute the dump.
 */
function register_stub_autoload()
{
    spl_autoload_register(function ($className) {
        if (!is_string($className) || !preg_match('/\A[A-Za-z_\\\\][A-Za-z0-9_\\\\]*\z/', $className)) {
            return;
        }
        if (class_exists($className, false) || interface_exists($className, false) || trait_exists($className, false)) {
            return;
        }
        $parts = explode('\\', ltrim($className, '\\'));
        $shortName = array_pop($parts);
        $extends = getenv('OPCODEDUMP_STUB_INVOKE') ? ' extends \\__OpcodedumpStub' : '';
        if ($parts) {
            eval('namespace ' . implode('\\', $parts) . '; class ' . $shortName . $extends . ' {}');
        } else {
            eval('class ' . $shortName . $extends . ' {}');
        }
        opcodedump_register_synthetic_class($className);
    }, true, true);
}

function opcodedump_define_if_missing($name, $value)
{
    if (!defined($name) && is_string($value) && $value !== '') {
        define($name, rtrim(str_replace('\\', '/', $value), '/') . '/');
    }
}

/**
 * When dumping an OpenCart admin file, predefine the DIR_* constants from the
 * upload/ layout so path-building literals decode during the stub-invoke pass.
 */
function opcodedump_autodefine_opencart_dirs($resolved)
{
    if (getenv('OPCODEDUMP_DISABLE_AUTODEFINE_OPENCART_DIRS')) {
        return;
    }
    if (!is_string($resolved) || $resolved === '') {
        return;
    }

    $path = str_replace('\\', '/', $resolved);
    $lower = strtolower($path);
    $marker = '/upload/admin/';
    $pos = strpos($lower, $marker);
    if ($pos === false) {
        return;
    }

    $uploadRoot = substr($path, 0, $pos + strlen('/upload/'));
    $adminRoot = $uploadRoot . 'admin/';
    $systemRoot = $uploadRoot . 'system/';
    $catalogRoot = $uploadRoot . 'catalog/';

    opcodedump_define_if_missing('DIR_APPLICATION', $adminRoot);
    opcodedump_define_if_missing('DIR_LANGUAGE', $adminRoot . 'language/');
    opcodedump_define_if_missing('DIR_TEMPLATE', $adminRoot . 'view/template/');
    opcodedump_define_if_missing('DIR_SYSTEM', $systemRoot);
    opcodedump_define_if_missing('DIR_CATALOG', $catalogRoot);
    opcodedump_define_if_missing('DIR_STORAGE', $systemRoot . 'storage/');
    opcodedump_define_if_missing('DIR_CONFIG', $systemRoot . 'config/');
    opcodedump_define_if_missing('DIR_CACHE', $systemRoot . 'storage/cache/');
    opcodedump_define_if_missing('DIR_DOWNLOAD', $systemRoot . 'storage/download/');
    opcodedump_define_if_missing('DIR_LOGS', $systemRoot . 'storage/logs/');
    opcodedump_define_if_missing('DIR_MODIFICATION', $systemRoot . 'storage/modification/');
    opcodedump_define_if_missing('DIR_SESSION', $systemRoot . 'storage/session/');
    opcodedump_define_if_missing('DIR_UPLOAD', $systemRoot . 'storage/upload/');
    opcodedump_define_if_missing('DIR_IMAGE', $uploadRoot . 'image/');
}
