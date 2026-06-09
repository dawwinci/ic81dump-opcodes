/*
  +----------------------------------------------------------------------+
  | opcodedump extension - PHP 8.1 ionCube opcode dumper                 |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_OPCODEDUMP_H
#define PHP_OPCODEDUMP_H

extern zend_module_entry opcodedump_module_entry;
#define phpext_opcodedump_ptr &opcodedump_module_entry

#define PHP_OPCODEDUMP_VERSION "0.1.0"

#ifdef PHP_WIN32
#	define PHP_OPCODEDUMP_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_OPCODEDUMP_API __attribute__ ((visibility("default")))
#else
#	define PHP_OPCODEDUMP_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#define OPCODEDUMP_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(opcodedump, v)

#if defined(ZTS) && defined(COMPILE_DL_OPCODEDUMP)
ZEND_TSRMLS_CACHE_EXTERN()
#endif

/* Modern Zend op_array layout (live_range, return type info at arg_info[-1],
 * etc.). This extension targets PHP 8.1, where it is always present. */
#if (PHP_MAJOR_VERSION >= 8)
# define ZEND_ENGINE_MODERN
#endif

#endif /* PHP_OPCODEDUMP_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
