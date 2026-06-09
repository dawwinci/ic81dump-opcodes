/*
  +----------------------------------------------------------------------+
  | opcodedump extension - PHP 8.1 ionCube opcode dumper (x86)           |
  +----------------------------------------------------------------------+
  | Target PHP    : 8.1.x NTS Win32 VS16 x86                             |
  | Target loader : ioncube_loader_win_8.1.dll                           |
  |                 (ioncube_loader_15.5_8.1.0_nonts.dll, ImageBase       |
  |                  0x10000000 typical; verify in IDA)                   |
  |                                                                      |
  | Loader RVAs (binary analysis of the 8.1 loader, used at runtime):    |
  |   IC_VM_LOOP_RVA     = 0x6FF10  (sub_1006FF10: loader VM dispatch)   |
  |   IC_REQUEST_KEY_RVA = 0xB01C8  (dword_101B01C8: per-request XOR key) |
  |                                                                      |
  | PHP 8.1 zend_op_array x86 offsets:                                   |
  |   [+0x30]=last  [+0x34]=opcodes*  [+0x5C]=filename* (XOR key salt)   |
  |   [+0x64]=line_end (encode marker bit 0x400000)                      |
  |   [+0x88]=reserved[3] (ionCube descriptor pointer)                   |
  |                                                                      |
  | Full-opcode recovery: the loader runs encoded functions through its  |
  | own VM loop (sub_1006FF10), bypassing zend_execute_ex, and stores a  |
  | permuted opline->opcode (dispatch is via the handler). We drive each |
  | functions through the loader VM (body skipped for safety). The top   |
  | level {main} is materialized through the loader's op_array decoder,  |
  | then deep-copied and restored so the root frame is not executed.      |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "Zend/zend_vm_opcodes.h"
#include "Zend/zend_exceptions.h"
#include "php_opcodedump.h"
#include <stdint.h>
#include <stdio.h>
#ifdef PHP_WIN32
#include <windows.h>
#include <intrin.h>
static int dasm_ic_committed_readable_ptr(const void *ptr);
#endif
#ifndef va_copy
# define va_copy(dst, src) ((dst) = (src))
#endif
/* PHP 8.0 removed the TSRM thread-context macros entirely. Provide empty
 * compatibility shims so the legacy call sites still compile. */
#ifndef TSRMLS_CC
# define TSRMLS_CC
# define TSRMLS_DC
# define TSRMLS_C
# define TSRMLS_D void
#endif
#ifndef IC_LOADER_NAME
#define IC_LOADER_NAME     "ioncube_loader_win_8.1.dll"
#endif

void dasm_zend_op_array(zval *dst, const zend_op_array *src);
static zend_uchar dasm_ic_display_opcode(const zend_op_array *op_array, const zend_op *opline,
                                          zend_uchar opcode);
static void inline dasm_zend_class_entry(zval *dst, zend_class_entry *src);
static int ic_env_flag_enabled(const char *name);

static inline uint32_t dasm_assoc_key_len(size_t key_len)
{
	return key_len > 0 ? (uint32_t)(key_len - 1) : 0;
}

static inline void dasm_add_assoc_long_ex(zval *arg, const char *key, size_t key_len, zend_long value)
{
	add_assoc_long_ex(arg, key, dasm_assoc_key_len(key_len), value);
}

static inline void dasm_add_assoc_bool_ex(zval *arg, const char *key, size_t key_len, zend_bool value)
{
	add_assoc_bool_ex(arg, key, dasm_assoc_key_len(key_len), value);
}

static inline void dasm_add_assoc_zval_ex(zval *arg, const char *key, size_t key_len, zval *value)
{
	add_assoc_zval_ex(arg, key, dasm_assoc_key_len(key_len), value);
}

static inline void dasm_add_assoc_null_ex(zval *arg, const char *key, size_t key_len)
{
	add_assoc_null_ex(arg, key, dasm_assoc_key_len(key_len));
}

static char *dasm_hex_encode(const unsigned char *data, size_t len)
{
	static const char hex[] = "0123456789abcdef";
	char *out;
	size_t i;

	if (data == NULL || len > 1048576) {
		return NULL;
	}

	out = (char *)emalloc((len * 2) + 1);
	for (i = 0; i < len; ++i) {
		out[i * 2] = hex[(data[i] >> 4) & 0x0f];
		out[i * 2 + 1] = hex[data[i] & 0x0f];
	}
	out[len * 2] = '\0';

	return out;
}

static void dasm_add_zend_string_and_hex(zval *dst, const char *field,
                                         const char *hex_field, zend_string *str)
{
	const char *value = NULL;
	size_t value_len = 0;
	char *hex = NULL;

	if (str == NULL) {
		add_assoc_null(dst, field);
		add_assoc_null(dst, hex_field);
		return;
	}

#ifdef PHP_WIN32
	__try {
		if (dasm_ic_committed_readable_ptr(str)) {
			value = ZSTR_VAL(str);
			value_len = ZSTR_LEN(str);
			if (value_len > 1048576 ||
			    !dasm_ic_committed_readable_ptr(value) ||
			    !dasm_ic_committed_readable_ptr(value + value_len)) {
				value = NULL;
				value_len = 0;
			}
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		value = NULL;
		value_len = 0;
	}
#else
	value = ZSTR_VAL(str);
	value_len = ZSTR_LEN(str);
#endif

	if (value == NULL) {
		add_assoc_null(dst, field);
		add_assoc_null(dst, hex_field);
		return;
	}

	add_assoc_stringl(dst, field, (char *)value, value_len);
	hex = dasm_hex_encode((const unsigned char *)value, value_len);
	if (hex) {
		add_assoc_string(dst, hex_field, hex);
		efree(hex);
	} else {
		add_assoc_null(dst, hex_field);
	}
}

#define add_assoc_long_ex dasm_add_assoc_long_ex
#define add_assoc_bool_ex dasm_add_assoc_bool_ex
#define add_assoc_zval_ex dasm_add_assoc_zval_ex
#define add_assoc_null_ex dasm_add_assoc_null_ex

/* The *_ex shims above follow a sizeof()-style convention: callers pass the key
 * length INCLUDING the trailing NUL (e.g. sizeof("key")) and the shim subtracts
 * one. PHP's own non-_ex helpers (add_assoc_long/bool/zval/null) expand to the
 * _ex form with strlen(key) (no NUL), which the shim would then wrongly shorten
 * by one character (e.g. "op_array" -> "op_arra"). Re-point the non-_ex helpers
 * to pass strlen(key)+1 so both conventions yield the correct, untruncated key.
 * (add_assoc_string/stringl are not shimmed, so they are already correct.) */
#undef add_assoc_long
#undef add_assoc_bool
#undef add_assoc_zval
#undef add_assoc_null
#define add_assoc_long(__a, __k, __n) add_assoc_long_ex(__a, __k, strlen(__k) + 1, __n)
#define add_assoc_bool(__a, __k, __n) add_assoc_bool_ex(__a, __k, strlen(__k) + 1, __n)
#define add_assoc_zval(__a, __k, __v) add_assoc_zval_ex(__a, __k, strlen(__k) + 1, __v)
#define add_assoc_null(__a, __k)      add_assoc_null_ex(__a, __k, strlen(__k) + 1)

static zend_op_array *(*opcodedump_orig_compile_file)(zend_file_handle *file_handle, int type) = NULL;
static void (*opcodedump_orig_execute_ex)(zend_execute_data *execute_data) = NULL;
static void (*opcodedump_orig_execute_internal)(zend_execute_data *execute_data, zval *return_value) = NULL;
static zval opcodedump_extra_function_table;
static zval opcodedump_extra_class_table;
static zval opcodedump_ioncube_call_log;
static uint32_t opcodedump_ioncube_call_seen = 0;
static uint32_t opcodedump_ioncube_call_captured = 0;
static uint32_t opcodedump_ioncube_call_truncated = 0;
static uint32_t opcodedump_ioncube_call_sequence = 0;
static char opcodedump_execute_hook_last_filename[4096];
static char opcodedump_execute_hook_last_function[1024];
static char opcodedump_compile_hook_last_before[4096];
static char opcodedump_compile_hook_last_after[4096];
static char opcodedump_compile_hook_last_oa[4096];

static zend_op_array *opcodedump_compile_file_hook(zend_file_handle *file_handle, int type);
static void opcodedump_execute_ex_hook(zend_execute_data *execute_data);
static void opcodedump_execute_internal_hook(zend_execute_data *execute_data, zval *return_value);
static int dasm_zend_function_name_is_safe(zend_function *fbc);

static void opcodedump_install_hooks(void)
{
	if (zend_compile_file != opcodedump_compile_file_hook) {
		opcodedump_orig_compile_file = zend_compile_file;
		zend_compile_file = opcodedump_compile_file_hook;
	}
	if (zend_execute_ex != opcodedump_execute_ex_hook) {
		opcodedump_orig_execute_ex = zend_execute_ex;
		zend_execute_ex = opcodedump_execute_ex_hook;
	}
	if (zend_execute_internal != opcodedump_execute_internal_hook) {
		opcodedump_orig_execute_internal = zend_execute_internal;
		zend_execute_internal = opcodedump_execute_internal_hook;
	}
}


void dasm_zend_arg_info(zval *dst, const zend_arg_info *src)
{
	if (src->name == NULL) {
		add_assoc_null(dst, "name");
		add_assoc_long(dst, "name_len", 0);
	} else {
		const char *_name = NULL;
		size_t _name_len = 0;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(src->name)) {
				_name = ZSTR_VAL(src->name);
				_name_len = ZSTR_LEN(src->name);
				if (_name_len > 32768 ||
				    !dasm_ic_committed_readable_ptr(_name) ||
				    !dasm_ic_committed_readable_ptr(_name + _name_len)) {
					_name = NULL;
					_name_len = 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_name = NULL;
			_name_len = 0;
		}
#else
		_name = ZSTR_VAL(src->name);
		_name_len = ZSTR_LEN(src->name);
#endif
		if (_name) {
			add_assoc_stringl(dst, "name", (char *)_name, _name_len);
			add_assoc_long(dst, "name_len", _name_len);
		} else {
			add_assoc_null(dst, "name");
			add_assoc_long(dst, "name_len", 0);
		}
	}

	/* PHP 8.x: zend_arg_info.type is a zend_type struct; class names live in the
	 * name slot, scalar type info in the type mask, send-mode/variadic in flags. */
	if (ZEND_TYPE_HAS_NAME(src->type)) {
		zend_string *cn = ZEND_TYPE_NAME(src->type);
		const char *_class_name = NULL;
		size_t _class_name_len = 0;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(cn)) {
				_class_name = ZSTR_VAL(cn);
				_class_name_len = ZSTR_LEN(cn);
				if (_class_name_len > 32768 ||
				    !dasm_ic_committed_readable_ptr(_class_name) ||
				    !dasm_ic_committed_readable_ptr(_class_name + _class_name_len)) {
					_class_name = NULL;
					_class_name_len = 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_class_name = NULL;
			_class_name_len = 0;
		}
#else
		_class_name = ZSTR_VAL(cn);
		_class_name_len = ZSTR_LEN(cn);
#endif
		if (_class_name) {
			add_assoc_stringl(dst, "class_name", (char *)_class_name, _class_name_len);
			add_assoc_long(dst, "class_name_len", (zend_long)_class_name_len);
		} else {
			add_assoc_null(dst, "class_name");
			add_assoc_long(dst, "class_name_len", 0);
		}
	} else {
		add_assoc_null(dst, "class_name");
		add_assoc_long(dst, "class_name_len", 0);
	}

	{
		/* PHP 8.x: scalar type hint is the pure type mask (IS_LONG, IS_STRING, ...). */
		zend_long type_code = (zend_long)ZEND_TYPE_PURE_MASK(src->type);
		add_assoc_long(dst, "type", type_code);
		add_assoc_long_ex(dst, ("type_hint"), (sizeof("type_hint")), type_code);
	}
	add_assoc_bool_ex(dst, ("pass_by_reference"), (sizeof("pass_by_reference")),
	                  (ZEND_ARG_SEND_MODE(src) != ZEND_SEND_BY_VAL) ? 1 : 0);
	add_assoc_bool_ex(dst, ("allow_null"), (sizeof("allow_null")), ZEND_TYPE_ALLOW_NULL(src->type) ? 1 : 0);
	add_assoc_bool_ex(dst, ("is_variadic"), (sizeof("is_variadic")), ZEND_ARG_IS_VARIADIC(src) ? 1 : 0);
}

static const char *dasm_znode_type_name(zend_uchar type)
{
	switch (type) {
		case IS_CONST:   return "IS_CONST";
		case IS_TMP_VAR: return "IS_TMP_VAR";
		case IS_VAR:     return "IS_VAR";
		case IS_UNUSED:  return "IS_UNUSED";
		case IS_CV:      return "IS_CV";
		default:         return NULL;
	}
}

static zend_long dasm_literal_index(const zend_op_array *op_array, const zval *literal)
{
	if (op_array == NULL || op_array->literals == NULL || literal == NULL) {
		return -1;
	}
	if (literal < op_array->literals || literal >= (op_array->literals + op_array->last_literal)) {
		return -1;
	}
	return (zend_long)(literal - op_array->literals);
}

#ifdef PHP_WIN32
static void dasm_add_handler_rva(zval *dst, const zend_op *src)
{
	HMODULE hLoader;
	uintptr_t loader_base;
	uintptr_t handler;

	if (dst == NULL || src == NULL || src->handler == NULL) return;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return;
	loader_base = (uintptr_t)hLoader;
	handler = (uintptr_t)src->handler;
	if (handler >= loader_base && handler < loader_base + 0x300000u) {
		add_assoc_long(dst, "handler_rva", (zend_long)(handler - loader_base));
	}
}
#endif

static zend_long dasm_normalize_fn_flags(uint32_t fn_flags)
{
	return (zend_long)(fn_flags & ~ZEND_ACC_DONE_PASS_TWO);
}

static int dasm_operand_is_jump_target(zend_uchar opcode, int operand_index)
{
	switch (opcode) {
		case ZEND_JMP:
		case ZEND_FAST_CALL:
			return operand_index == 1;
		case ZEND_JMPZ:
		case ZEND_JMPNZ:
		case ZEND_JMPZNZ:
		case ZEND_JMPZ_EX:
		case ZEND_JMPNZ_EX:
		case ZEND_FE_RESET_R:
		case ZEND_FE_RESET_RW:
		case ZEND_JMP_SET:
		case ZEND_COALESCE:
		case ZEND_ASSERT_CHECK:
		case ZEND_CATCH:
			return operand_index == 2;
		default:
			return 0;
	}
}

static int dasm_operand_is_effective_jump_target(const zend_op *opline,
                                                  zend_uchar opcode,
                                                  int operand_index)
{
	if (!dasm_operand_is_jump_target(opcode, operand_index)) {
		return 0;
	}
	if (opcode == ZEND_CATCH && operand_index == 2 && opline != NULL &&
	    (opline->extended_value & ZEND_LAST_CATCH)) {
		return 0;
	}
	return 1;
}

/* ---- ionCube helper forward decls (Windows-only) ---- */
#ifdef PHP_WIN32
static void *ic_lookup_desc(const zend_op_array *op_array);
static int   dasm_ic_committed_readable_ptr(const void *ptr);
#endif

static zend_long dasm_index_from_address_base(uintptr_t raw, uintptr_t base, uint32_t last)
{
	uintptr_t size;
	if (base == 0 || raw < base || last == 0) {
		return -1;
	}
	size = (uintptr_t)last * sizeof(zend_op);
	if (raw >= base + size || ((raw - base) % sizeof(zend_op)) != 0) {
		return -1;
	}
	return (zend_long)((raw - base) / sizeof(zend_op));
}

static zend_long dasm_jump_target_index(const zend_op_array *op_array, const zend_op *opline,
                                         zend_uchar opcode, int operand_index, znode_op operand)
{
	zend_long current_index;
	zend_long target_index = -1;

	if (op_array == NULL || op_array->opcodes == NULL ||
	    !dasm_operand_is_effective_jump_target(opline, opcode, operand_index)) {
		return -1;
	}

	current_index = (opline != NULL) ? (zend_long)(opline - op_array->opcodes) : -1;

#if ZEND_USE_ABS_JMP_ADDR
	target_index = dasm_index_from_address_base(
	    (uintptr_t)operand.jmp_addr, (uintptr_t)op_array->opcodes, op_array->last);
#else
	{
		const zend_op *target = (const zend_op *)((const char *)&operand + operand.jmp_offset);
		if (target >= op_array->opcodes && target < (op_array->opcodes + op_array->last)) {
			target_index = (zend_long)(target - op_array->opcodes);
		}
	}
#endif

	return target_index;
}

static zend_long dasm_operand_value(const zend_op_array *op_array, const zend_op *opline,
                                     zend_uchar opcode, int operand_index,
                                     zend_uchar type, znode_op operand, zend_long constant_index)
{
	zend_long jump_target = dasm_jump_target_index(op_array, opline, opcode, operand_index, operand);
	if (jump_target >= 0) return jump_target;
	if (type == IS_CONST && constant_index >= 0) return constant_index;
	return (zend_long)operand.var;
}

#ifdef PHP_WIN32
static void dasm_copy_zend_op_safe(zend_op *dst, const zend_op *src)
{
	memset(dst, 0, sizeof(*dst));
	if (src == NULL) return;

	__try { dst->handler = src->handler; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->op1 = src->op1; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->op2 = src->op2; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->result = src->result; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->extended_value = src->extended_value; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->lineno = src->lineno; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->opcode = src->opcode; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->op1_type = src->op1_type; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->op2_type = src->op2_type; } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dst->result_type = src->result_type; } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

static zend_long dasm_operand_value_safe(const zend_op_array *op_array, const zend_op *opline,
                                          zend_uchar opcode, int operand_index,
                                          zend_uchar type, znode_op operand,
                                          zend_long constant_index, zend_long fallback)
{
	zend_long value = fallback;
	if (dasm_operand_is_effective_jump_target(opline, opcode, operand_index) && opline != NULL) {
		__try {
			znode_op raw_operand = operand_index == 1 ? opline->op1 : opline->op2;
			value = dasm_jump_target_index(op_array, opline, opcode, operand_index, raw_operand);
			if (value >= 0) return value;
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			value = fallback;
		}
	}
	__try {
		value = dasm_operand_value(op_array, opline, opcode, operand_index,
		                           type, operand, constant_index);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		value = -1;
		__try {
			if (dasm_operand_is_effective_jump_target(opline, opcode, operand_index) && opline != NULL) {
				znode_op raw_operand = operand_index == 1 ? opline->op1 : opline->op2;
				value = dasm_jump_target_index(op_array, opline, opcode, operand_index, raw_operand);
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			value = -1;
		}
		if (value < 0) value = fallback;
	}
	return value;
}
#endif

static void dasm_add_literal(zval *dst, const char *key,
                              const zend_op_array *op_array, zend_uchar type, znode_op operand)
{
	zend_long literal_index;
	zval literal;

	if (type != IS_CONST || operand.zv == NULL) return;
	literal_index = dasm_literal_index(op_array, operand.zv);
	if (literal_index < 0) return;
	ZVAL_DUP(&literal, operand.zv);
	add_assoc_zval(dst, key, &literal);
}

static int dasm_is_printable_identifier_bytes(const char *s, size_t len)
{
	size_t i;
	if (s == NULL || len == 0) return 0;
	for (i = 0; i < len; ++i) {
		unsigned char c = (unsigned char)s[i];
		if (c < 0x20 || c > 0x7e) return 0;
	}
	return 1;
}

static void dasm_add_var_name_stringl(zval *dst, const char *key, const char *s, size_t len)
{
	if (dasm_is_printable_identifier_bytes(s, len)) {
		add_assoc_stringl(dst, key, (char *)s, len);
	} else {
		static const char prefix[] = "_obfuscated_";
		size_t out_len = (sizeof(prefix) - 1) + (len * 2) + 1;
		char *out = (char *)emalloc(out_len + 1);
		size_t i, p = 0;
		memcpy(out, prefix, sizeof(prefix) - 1);
		p += sizeof(prefix) - 1;
		for (i = 0; i < len; ++i) {
			static const char hex[] = "0123456789ABCDEF";
			unsigned char c = (unsigned char)s[i];
			out[p++] = hex[c >> 4];
			out[p++] = hex[c & 0x0f];
		}
		out[p++] = '_';
		out[p] = '\0';
		add_assoc_stringl(dst, key, out, p);
		efree(out);
	}
}

/* Resolves an IS_CV operand byte-offset to the human-readable variable name
 * stored in op_array->vars[].  The byte offset encodes the CV slot as:
 *   offset = (ZEND_CALL_FRAME_SLOT + cv_index) * sizeof(zval)
 * so we subtract the frame-slot before indexing vars[]. */
static void dasm_add_cv_name(zval *dst, const char *key,
                              const zend_op_array *op_array,
                              zend_uchar type, znode_op operand)
{
	uint32_t cv_slot, cv_index;
	zend_string *var_name;

	if (type != IS_CV) return;
	if (op_array == NULL || op_array->vars == NULL || op_array->last_var == 0) return;

	cv_slot  = (uint32_t)operand.var / (uint32_t)sizeof(zval);
	if (cv_slot < (uint32_t)ZEND_CALL_FRAME_SLOT) return;
	cv_index = cv_slot - (uint32_t)ZEND_CALL_FRAME_SLOT;
	if (cv_index >= (uint32_t)op_array->last_var) return;

	var_name = op_array->vars[cv_index];
	if (var_name == NULL) return;

#ifdef PHP_WIN32
	__try {
		if (!dasm_ic_committed_readable_ptr(var_name)) return;
		{
			const char *_vname = ZSTR_VAL(var_name);
			size_t      _vlen  = ZSTR_LEN(var_name);
			if (_vlen == 0 || _vlen > 32768 ||
			    !dasm_ic_committed_readable_ptr(_vname) ||
			    !dasm_ic_committed_readable_ptr(_vname + _vlen)) return;
			dasm_add_var_name_stringl(dst, key, _vname, _vlen);
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
	dasm_add_var_name_stringl(dst, key, ZSTR_VAL(var_name), ZSTR_LEN(var_name));
#endif
}

/* ============================================================
 * ionCube descriptor map  (Windows only)
 * ============================================================ */
#ifdef PHP_WIN32
#ifndef IC_KEY_TABLE_RVA
#define IC_KEY_TABLE_RVA   0u  /* legacy = 0x1A128C; not re-located for 8.1 v15.5 (advanced literal pass disabled) */
#endif
#ifndef IC_REQUEST_KEY_RVA
#define IC_REQUEST_KEY_RVA 0xB01C8u  /* 8.1 v15.5: dword_101B01C8 (per-request XOR key) */
#endif
#ifndef IC_STEP1_RVA
#define IC_STEP1_RVA 0x2C50u  /* sub_10002C50: materialize an encoded op_array body */
#endif
#ifndef IC_OPCODE_SETTER_RVA
#define IC_OPCODE_SETTER_RVA 0x701D0u
#endif
#ifndef IC_DESCRIPTOR_PREPROCESS_PATCH_RVA
#define IC_DESCRIPTOR_PREPROCESS_PATCH_RVA 0x6CE45u
#endif
#define IC_DESC_MAP_MAX 4096
#define OPCODEDUMP_DESCRIPTOR_SAVE_MAX 512
#define OPCODEDUMP_PATCH_LEN 5

static const zend_op_array *ic_desc_map_oa[IC_DESC_MAP_MAX];
static void *ic_desc_map_desc[IC_DESC_MAP_MAX];
static uint32_t ic_desc_map_count = 0;
static int ic_env_flag_enabled(const char *name);
/* Per-stage counters for the literal-decode early returns (diagnostics only) */
static volatile LONG ic_decode_seh_phase = 0;
static DWORD ic_decode_seh_code = 0;
static zend_long ic_decode_seh_index = -1;
static unsigned char opcodedump_descriptor_original[OPCODEDUMP_PATCH_LEN];
static void *opcodedump_descriptor_target = NULL;
static int opcodedump_descriptor_hook_installed = 0;
static uintptr_t opcodedump_loader_base_cached = 0;
static int opcodedump_descriptor_in_hook = 0;
static uint32_t opcodedump_descriptor_extra_functions = 0;
static uintptr_t opcodedump_descriptor_words[16] = {0};
static uintptr_t opcodedump_descriptor_class_entries[8] = {0};
static uintptr_t opcodedump_descriptor_function_entries[8] = {0};
static uintptr_t opcodedump_descriptor_first_function_entry_words[12] = {0};
static uintptr_t opcodedump_descriptor_first_class_entry_words[12] = {0};
static uintptr_t opcodedump_descriptor_first_function_oa_words[32] = {0};
static void *opcodedump_descriptor_last_module = NULL;
static int opcodedump_descriptor_capture_enabled = 0;
static zend_op_array *opcodedump_descriptor_saved_functions[OPCODEDUMP_DESCRIPTOR_SAVE_MAX];
static uint32_t opcodedump_descriptor_saved_function_count = 0;
static zend_class_entry *opcodedump_descriptor_saved_classes[OPCODEDUMP_DESCRIPTOR_SAVE_MAX];
static uint32_t opcodedump_descriptor_saved_class_count = 0;
#define IC_DYNAMIC_SAVED_MAX 256
typedef struct _ic_dynamic_saved_op_array {
	zend_op_array *oa;
	zend_op_array copy;
	uint32_t valid;
	uint32_t saves;
	uintptr_t desc;
	uintptr_t desc19;
	char name[128];
	char scope[128];
} ic_dynamic_saved_op_array;
static ic_dynamic_saved_op_array ic_dynamic_saved_generic[IC_DYNAMIC_SAVED_MAX];
static uint32_t ic_dynamic_saved_generic_count = 0;
static uint32_t ic_dynamic_saved_generic_valid_count = 0;
#define OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE 262144u
typedef struct _opcodedump_opcode_capture_entry {
	uintptr_t opline;
	zend_uchar opcode;
	uint32_t hits;
} opcodedump_opcode_capture_entry;
static opcodedump_opcode_capture_entry opcodedump_opcode_capture_map[OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE];
static int opcodedump_opcode_capture_hook_installed = 0;
static int opcodedump_opcode_setter_hook_installed = 0;
typedef int (__fastcall *ic_dynamic_op_array_materialize_fn)(zend_op_array *op_array);
typedef unsigned char (__fastcall *ic_dynamic_key_resolve_fn)(void *key_spec, char *edx_arg,
                                                              uint32_t arg0, uint32_t arg4, uint32_t arg8,
                                                              uint32_t *out_key, uint32_t *out_len);
typedef char *(__fastcall *ic_function_name_encode_fn)(const char *name, uint32_t name_len,
                                                       const void *salt, uint32_t salt_len,
                                                       uint32_t marker);
static int opcodedump_loader_bytes_match_mask(uintptr_t rva, const unsigned char *bytes,
                                              const char *mask, size_t len);
static void __fastcall opcodedump_process_module_descriptor(void *module_desc, uintptr_t loader_base);
static void opcodedump_capture_extra_function(const char *name, size_t name_len,
                                              zend_op_array *oa, uintptr_t loader_base);
static void opcodedump_capture_extra_class(zend_class_entry *ce, uintptr_t loader_base);


static uintptr_t ic_dynamic_read_desc19(zend_op_array *oa)
{
	void *ic_desc;
	uintptr_t desc19 = 0;
	if (!oa) return 0;
	ic_desc = oa->reserved[3];
	if (!ic_desc || !dasm_ic_committed_readable_ptr(ic_desc) ||
	    !dasm_ic_committed_readable_ptr((const char *)ic_desc + 80)) {
		return 0;
	}
	__try {
		desc19 = (uintptr_t)((uint32_t *)ic_desc)[19];
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		desc19 = 0;
	}
	return desc19;
}

static void ic_dynamic_copy_oa_identity(ic_dynamic_saved_op_array *entry, zend_op_array *oa)
{
	const char *name = NULL;
	const char *scope = NULL;
	if (!entry || !oa) return;
	entry->name[0] = '\0';
	entry->scope[0] = '\0';
	__try {
		if (oa->function_name) name = ZSTR_VAL(oa->function_name);
		if (oa->scope && oa->scope->name) scope = ZSTR_VAL(oa->scope->name);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		name = NULL;
		scope = NULL;
	}
	if (name) snprintf(entry->name, sizeof(entry->name), "%s", name);
	if (scope) snprintf(entry->scope, sizeof(entry->scope), "%s", scope);
}


static ic_dynamic_saved_op_array *ic_dynamic_find_saved_for_dump(zend_op_array *oa, zend_string *table_key)
{
	uint32_t i;
	const char *key = NULL;
	const char *scope = NULL;
	uintptr_t desc19;

	if (table_key) key = ZSTR_VAL(table_key);
	__try {
		if (oa && oa->scope && oa->scope->name) scope = ZSTR_VAL(oa->scope->name);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		scope = NULL;
	}
	desc19 = ic_dynamic_read_desc19(oa);
	for (i = 0; i < ic_dynamic_saved_generic_count; ++i) {
		ic_dynamic_saved_op_array *entry = &ic_dynamic_saved_generic[i];
		if (!entry->valid) continue;
		if (oa && entry->oa == oa) return entry;
		if (desc19 && entry->desc19 == desc19) return entry;
		if (key && entry->name[0] && _stricmp(entry->name, key) == 0) {
			if (!scope || !entry->scope[0] || _stricmp(entry->scope, scope) == 0) {
				return entry;
			}
		}
	}
	return NULL;
}

static ic_dynamic_saved_op_array *ic_dynamic_register_saved(zend_op_array *oa)
{
	uint32_t i;
	uintptr_t desc19;
	void *ic_desc;
	ic_dynamic_saved_op_array *entry;

	if (!oa) return NULL;
	desc19 = ic_dynamic_read_desc19(oa);
	ic_desc = oa->reserved[3];
	for (i = 0; i < ic_dynamic_saved_generic_count; ++i) {
		entry = &ic_dynamic_saved_generic[i];
		if ((desc19 && entry->desc19 == desc19) || entry->oa == oa) {
			entry->oa = oa;
			if (ic_desc) entry->desc = (uintptr_t)ic_desc;
			if (desc19) entry->desc19 = desc19;
			ic_dynamic_copy_oa_identity(entry, oa);
			return entry;
		}
	}
	if (ic_dynamic_saved_generic_count >= IC_DYNAMIC_SAVED_MAX) return NULL;
	entry = &ic_dynamic_saved_generic[ic_dynamic_saved_generic_count++];
	memset(entry, 0, sizeof(*entry));
	entry->oa = oa;
	entry->desc = (uintptr_t)ic_desc;
	entry->desc19 = desc19;
	ic_dynamic_copy_oa_identity(entry, oa);
	return entry;
}

static uint32_t opcodedump_opcode_capture_hash(uintptr_t opline)
{
	return (uint32_t)(((opline >> 2) * 2654435761u) & (OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE - 1u));
}

static void opcodedump_opcode_capture_reset_map(void)
{
	memset(opcodedump_opcode_capture_map, 0, sizeof(opcodedump_opcode_capture_map));
}


static void __cdecl opcodedump_capture_materialized_opcode(zend_op *opline, unsigned int opcode)
{
	uintptr_t key = (uintptr_t)opline;
	uint32_t idx, n;

	if (!key || (key & 3u) != 0) {
		return;
	}

	idx = opcodedump_opcode_capture_hash(key);
	for (n = 0; n < OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE; ++n) {
		opcodedump_opcode_capture_entry *entry =
		    &opcodedump_opcode_capture_map[(idx + n) & (OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE - 1u)];
		if (entry->opline == key) {
			entry->opcode = (zend_uchar)(opcode & 0xffu);
			entry->hits++;
			return;
		}
		if (entry->opline == 0) {
			entry->opline = key;
			entry->opcode = (zend_uchar)(opcode & 0xffu);
			entry->hits = 1;
			return;
		}
	}
}

static int opcodedump_lookup_captured_opcode(const zend_op *opline, zend_uchar *opcode_out)
{
	uintptr_t key = (uintptr_t)opline;
	uint32_t idx, n;

	if (!key || (key & 3u) != 0) return 0;

	idx = opcodedump_opcode_capture_hash(key);
	for (n = 0; n < OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE; ++n) {
		opcodedump_opcode_capture_entry *entry =
		    &opcodedump_opcode_capture_map[(idx + n) & (OPCODEDUMP_OPCODE_CAPTURE_MAP_SIZE - 1u)];
		if (entry->opline == key) {
			if (opcode_out) *opcode_out = entry->opcode;
			return 1;
		}
		if (entry->opline == 0) return 0;
	}
	return 0;
}

static void opcodedump_apply_captured_opcodes_to_copy(zend_op_array *copy,
                                                       const zend_op *old_ops,
                                                       uint32_t old_last)
{
	uint32_t i, n;
	if (!copy || !copy->opcodes || !old_ops || old_last == 0) return;
	n = copy->last;
	if (n > old_last) n = old_last;
	for (i = 0; i < n; ++i) {
		zend_uchar opcode;
		if (opcodedump_lookup_captured_opcode(old_ops + i, &opcode)) {
			copy->opcodes[i].opcode = opcode;
		}
	}
}

#ifdef PHP_WIN32
/* step1 materializes opcodes/literals into transient loader memory that is freed
 * shortly after the call returns, so a later serialization pass reads freed
 * pages. Deep-copy both arrays into stable process memory and rebase the
 * intra-array absolute pointers (x86 PHP 8.1 uses ZEND_USE_ABS_JMP/CONST_ADDR:
 * jump targets point into opcodes, IS_CONST operands point into literals).
 * The copies intentionally outlive the request (one-shot dump process). */
static void ic_deep_copy_op_array_body(zend_op_array *copy)
{
	zend_op *old_ops, *new_ops = NULL;
	zval *old_lits, *new_lits = NULL;
	uint32_t nops, i;
	int nlit;
	uintptr_t ops_lo, ops_hi, lit_lo, lit_hi;

	if (!copy) return;
	old_ops = copy->opcodes;
	old_lits = copy->literals;
	nops = copy->last;
	nlit = copy->last_literal;
	if (!old_ops || ((uintptr_t)old_ops & 3) || nops == 0 || nops >= 65536) return;

	ops_lo = (uintptr_t)old_ops;
	ops_hi = ops_lo + (uintptr_t)nops * sizeof(zend_op);
	lit_lo = (uintptr_t)old_lits;
	lit_hi = lit_lo + (uintptr_t)(nlit > 0 ? (uint32_t)nlit : 0) * sizeof(zval);

	if (old_lits && nlit > 0 && nlit < 65536) {
		new_lits = (zval *)malloc((size_t)nlit * sizeof(zval));
		if (new_lits) {
			__try { memcpy(new_lits, old_lits, (size_t)nlit * sizeof(zval)); }
			__except(EXCEPTION_EXECUTE_HANDLER) { free(new_lits); new_lits = NULL; }
		}
	}

	new_ops = (zend_op *)malloc((size_t)nops * sizeof(zend_op));
	if (!new_ops) { if (new_lits) free(new_lits); return; }
	__try { memcpy(new_ops, old_ops, (size_t)nops * sizeof(zend_op)); }
	__except(EXCEPTION_EXECUTE_HANDLER) { free(new_ops); if (new_lits) free(new_lits); return; }

	for (i = 0; i < nops; ++i) {
		uintptr_t v;
		v = (uintptr_t)new_ops[i].op1.jmp_addr;
		if (v >= ops_lo && v < ops_hi)
			new_ops[i].op1.jmp_addr = (zend_op *)((char *)new_ops + (v - ops_lo));
		else if (new_lits && v >= lit_lo && v < lit_hi)
			new_ops[i].op1.zv = (zval *)((char *)new_lits + (v - lit_lo));
		v = (uintptr_t)new_ops[i].op2.jmp_addr;
		if (v >= ops_lo && v < ops_hi)
			new_ops[i].op2.jmp_addr = (zend_op *)((char *)new_ops + (v - ops_lo));
		else if (new_lits && v >= lit_lo && v < lit_hi)
			new_ops[i].op2.zv = (zval *)((char *)new_lits + (v - lit_lo));
	}

	copy->opcodes = new_ops;
	if (new_lits) copy->literals = new_lits;
}

static int ic_opcode_may_need_lazy_branch_fixup(zend_uchar opcode)
{
	switch (opcode) {
		case ZEND_JMP:
		case ZEND_JMPZ:
		case ZEND_JMPNZ:
		case ZEND_JMPZNZ:
		case ZEND_JMPZ_EX:
		case ZEND_JMPNZ_EX:
		case ZEND_JMP_SET:
			return 1;
		default:
			return 0;
	}
}

static int ic_read_u32_ptr(const void *ptr, uint32_t *out)
{
	if (out) *out = 0;
	if (!ptr || !dasm_ic_committed_readable_ptr(ptr)) return 0;
	__try {
		if (out) *out = *(const uint32_t *)ptr;
		return 1;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		if (out) *out = 0;
		return 0;
	}
}

static int ic_read_u32_indirect(const uint32_t *ctx, uint32_t word_index, uint32_t *out)
{
	uint32_t ptr32 = 0;
	if (!ic_read_u32_ptr(ctx + word_index, &ptr32)) return 0;
	return ic_read_u32_ptr((const void *)(uintptr_t)ptr32, out);
}

static int ic_read_shuffle_a(const uint32_t *shuffle_a, uint32_t index, uint32_t *out)
{
	if (!shuffle_a) {
		if (out) *out = 0;
		return 1;
	}
	return ic_read_u32_ptr((const char *)shuffle_a + (uintptr_t)index * sizeof(uint32_t), out);
}

static int ic_read_shuffle_b(const uint32_t *shuffle_b, uint32_t index, uint32_t *out)
{
	if (out) *out = 0;
	if (!shuffle_b || index == 0) return 1;
	return ic_read_u32_ptr((const char *)shuffle_b + (uintptr_t)(index - 1u) * sizeof(uint32_t), out);
}

static int ic_branch_fixup_seed(const uint32_t *ctx, uint32_t window_len, uint32_t *step_out)
{
	uint32_t c0, c1, c2, c3, p4, p5, p6, p7;
	uint32_t denom;
	uint32_t step;

	if (step_out) *step_out = 0;
	if (window_len == 0 || !ctx || !dasm_ic_committed_readable_ptr(ctx + 7)) return 0;
	if (!ic_read_u32_ptr(ctx + 0, &c0)) return 0;
	if (!ic_read_u32_ptr(ctx + 1, &c1)) return 0;
	if (!ic_read_u32_ptr(ctx + 2, &c2)) return 0;
	if (!ic_read_u32_ptr(ctx + 3, &c3)) return 0;
	if (!ic_read_u32_indirect(ctx, 4, &p4)) return 0;
	if (!ic_read_u32_indirect(ctx, 5, &p5)) return 0;
	if (!ic_read_u32_indirect(ctx, 6, &p6)) return 0;
	if (!ic_read_u32_indirect(ctx, 7, &p7)) return 0;

	denom = p5 + p4 + c3 + c2 + c0 + c1 + p6 + 17u;
	if (denom == 0) denom = 1;
	step = (uint32_t)(p6 + p5 + p4 + c3 + c2 + c1 + c0 + (p7 % denom));
	step %= window_len;
	if (step == 0) step = 1;
	if (step_out) *step_out = step;
	return 1;
}

static void ic_fixup_one_lazy_branch_target(zend_op_array *copy, zend_op *opline,
                                            znode_op *target_operand,
                                            const uint32_t *ctx,
                                            const uint32_t *shuffle_a,
                                            const uint32_t *shuffle_b)
{
	zend_long current_index;
	zend_long target_index;
	uint32_t current_shuffle = 0;
	uint32_t end_shuffle = 0;
	uint32_t post_shuffle = 0;
	uint32_t step = 0;
	zend_long pivot_index;
	zend_long range_start, range_end, range_base;
	zend_long window_len;
	zend_long decoded_index;

	if (!copy || !copy->opcodes || !opline || !target_operand || !ctx) return;
	if ((opline->lineno & 0x200000u) != 0) return;

	current_index = (zend_long)(opline - copy->opcodes);
	if (current_index < 0 || current_index >= (zend_long)copy->last) return;

	target_index = dasm_index_from_address_base((uintptr_t)target_operand->jmp_addr,
	                                            (uintptr_t)copy->opcodes, copy->last);
	if (target_index < 0) return;

	if (!ic_read_shuffle_a(shuffle_a, (uint32_t)current_index, &current_shuffle)) return;
	pivot_index = current_index - (zend_long)current_shuffle;
	if (pivot_index < 0 || pivot_index >= (zend_long)copy->last) return;

	if (target_index >= pivot_index) {
		if (!ic_read_shuffle_a(shuffle_a, copy->last - 1u, &end_shuffle)) return;
		range_start = pivot_index + 1;
		range_end = (zend_long)copy->last - 1 - (zend_long)end_shuffle;
		range_base = 0;
	} else {
		range_start = 0;
		range_end = pivot_index - 1;
		range_base = 0;
	}
	if (range_start < 0 || range_end < range_start || range_end >= (zend_long)copy->last) return;

	window_len = range_end - range_start + 1;
	if (!ic_branch_fixup_seed(ctx, (uint32_t)window_len, &step)) return;

	decoded_index = target_index - (zend_long)step;
	while (decoded_index < range_start) {
		decoded_index = range_end + 1 + (decoded_index - range_start);
	}
	while (decoded_index > range_end) {
		decoded_index = range_start + (decoded_index - range_end - 1);
	}

	if (shuffle_a) {
		zend_long shuffle_index = decoded_index - range_base;
		if (shuffle_index < 0 || shuffle_index >= (zend_long)copy->last) return;
		if (!ic_read_shuffle_b(shuffle_b, (uint32_t)shuffle_index, &post_shuffle)) return;
		decoded_index += (zend_long)post_shuffle;
	}

	if (decoded_index < 0 || decoded_index >= (zend_long)copy->last) return;
	target_operand->jmp_addr = copy->opcodes + decoded_index;
	opline->lineno |= 0x200000u;
}

static void ic_fixup_lazy_branch_targets(zend_op_array *copy)
{
	uint32_t *desc;
	const uint32_t *ctx;
	const uint32_t *shuffle_a;
	const uint32_t *shuffle_b;
	uint32_t i;

	if (copy == NULL || copy->opcodes == NULL || copy->last == 0 || copy->last >= 65536) return;
	desc = (uint32_t *)copy->reserved[3];
	if (desc == NULL || !dasm_ic_committed_readable_ptr(desc + 26)) return;
	ctx = (const uint32_t *)((const char *)desc + 0x1c);
	if (!dasm_ic_committed_readable_ptr(ctx + 7)) return;
	shuffle_a = desc[25] ? (const uint32_t *)(uintptr_t)desc[25] : NULL;
	shuffle_b = desc[26] ? (const uint32_t *)(uintptr_t)desc[26] : NULL;

	for (i = 0; i < copy->last; ++i) {
		zend_op *opline = copy->opcodes + i;
		zend_uchar opcode = opline->opcode;
		if (!ic_opcode_may_need_lazy_branch_fixup(opcode)) continue;
		__try {
			switch (opcode) {
				case ZEND_JMP:
					ic_fixup_one_lazy_branch_target(copy, opline, &opline->op1,
					                                ctx, shuffle_a, shuffle_b);
					break;
				case ZEND_JMPZ:
				case ZEND_JMPNZ:
				case ZEND_JMPZNZ:
				case ZEND_JMPZ_EX:
				case ZEND_JMPNZ_EX:
				case ZEND_JMP_SET:
					ic_fixup_one_lazy_branch_target(copy, opline, &opline->op2,
					                                ctx, shuffle_a, shuffle_b);
					break;
				default:
					break;
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
	}
}
#endif

static void ic_dynamic_save_entry_copy(ic_dynamic_saved_op_array *entry, zend_op_array *oa)
{
	zend_op *capture_old_ops;
	uint32_t capture_old_last;

	if (!entry || !oa) return;
	if (!oa->last && oa->opcodes && ((uintptr_t)oa->opcodes & 3) == 0) {
		uint32_t t = *(uint32_t *)((char *)oa + 0x28);
		if (t > 0 && t < 0x10000) {
			oa->last = t;
		}
	}
	if (!oa->opcodes || ((uintptr_t)oa->opcodes & 3) != 0 || oa->last == 0) return;
	capture_old_ops = oa->opcodes;
	capture_old_last = oa->last;
	if (!entry->valid) ic_dynamic_saved_generic_valid_count++;
	memcpy(&entry->copy, oa, sizeof(entry->copy));
#ifdef PHP_WIN32
	/* Stabilize the transient step1 opcode/literal memory into the snapshot. */
	__try { ic_deep_copy_op_array_body(&entry->copy); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { opcodedump_apply_captured_opcodes_to_copy(&entry->copy, capture_old_ops, capture_old_last); }
	__except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { ic_fixup_lazy_branch_targets(&entry->copy); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif
	entry->valid = 1;
	entry->saves++;
	entry->oa = oa;
	if (!entry->desc && oa->reserved[3]) entry->desc = (uintptr_t)oa->reserved[3];
	if (!entry->desc19) entry->desc19 = ic_dynamic_read_desc19(oa);
	ic_dynamic_copy_oa_identity(entry, oa);
}


static void ic_remember_desc(const zend_op_array *op_array, void *desc)
{
	uint32_t i;
	if (op_array == NULL || desc == NULL) return;
	for (i = 0; i < ic_desc_map_count; ++i) {
		if (ic_desc_map_oa[i] == op_array) {
			ic_desc_map_desc[i] = desc;
			return;
		}
	}
	if (ic_desc_map_count < IC_DESC_MAP_MAX) {
		ic_desc_map_oa[ic_desc_map_count]   = op_array;
		ic_desc_map_desc[ic_desc_map_count] = desc;
		ic_desc_map_count++;
	}
}

static void *ic_lookup_desc(const zend_op_array *op_array)
{
	uint32_t i;
	if (op_array == NULL) return NULL;
	if (op_array->reserved[3] != NULL) return op_array->reserved[3];
	for (i = 0; i < ic_desc_map_count; ++i) {
		if (ic_desc_map_oa[i] == op_array) return ic_desc_map_desc[i];
	}
	return NULL;
}

static int dasm_ic_committed_readable_ptr(const void *ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (ptr == NULL || !VirtualQuery(ptr, &mbi, sizeof(mbi))) return 0;
	if (mbi.State != MEM_COMMIT ||
	    mbi.Protect == PAGE_NOACCESS ||
	    mbi.Protect == PAGE_EXECUTE) return 0;
	return 1;
}

static int ic_env_flag_enabled(const char *name)
{
	char buf[32];
	DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
	if (n == 0) return 0;
	if (n >= sizeof(buf)) return 1;
	if (buf[0] == '\0' ||
	    buf[0] == '0' ||
	    buf[0] == 'n' || buf[0] == 'N' ||
	    buf[0] == 'f' || buf[0] == 'F') {
		return 0;
	}
	if ((buf[0] == 'o' || buf[0] == 'O') &&
	    (buf[1] == 'f' || buf[1] == 'F')) {
		return 0;
	}
	return 1;
}

static int dasm_ic_key_material_for_index(const zend_op_array *op_array, zend_long op_index,
                                            zend_uchar *key_byte_out, uint32_t *key_dword_out)
{
	HMODULE hLoader;
	uint32_t key_table;
	const uint32_t *desc;
	void *desc_ptr;
	uint32_t key_index;
	uintptr_t key_entry_addr;
	const uint8_t *key_stream;
	const uint32_t *key_stream32;

	if (key_byte_out)  *key_byte_out  = 0;
	if (key_dword_out) *key_dword_out = 0;

	if (op_array == NULL || op_index < 0 || op_index >= (zend_long)op_array->last) return 0;

	if (IC_KEY_TABLE_RVA == 0) return 0; /* RVA not yet filled */

	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader || !dasm_ic_committed_readable_ptr((const void *)((uintptr_t)hLoader + IC_KEY_TABLE_RVA)))
		return 0;

	desc_ptr = ic_lookup_desc(op_array);
	desc = (const uint32_t *)desc_ptr;
	if (!dasm_ic_committed_readable_ptr(desc)) return 0;

	key_table = *(const uint32_t *)((uintptr_t)hLoader + IC_KEY_TABLE_RVA);
	key_index = desc[1];
	if (key_table == 0 || key_index == 0xFFFFFFFFu || key_index > 4096) return 0;

	key_entry_addr = (uintptr_t)key_table + (uintptr_t)key_index * sizeof(uint32_t);
	if (!dasm_ic_committed_readable_ptr((const void *)key_entry_addr)) return 0;

	key_stream = *(const uint8_t * const *)key_entry_addr;
	if (!dasm_ic_committed_readable_ptr(key_stream + op_index)) return 0;
	key_stream32 = (const uint32_t *)key_stream;
	if (!dasm_ic_committed_readable_ptr(key_stream32 + op_index)) return 0;

	if (key_byte_out)  *key_byte_out  = key_stream[op_index];
	if (key_dword_out) *key_dword_out = key_stream32[op_index];
	return 1;
}

/* ============================================================
 * Handler -> opcode map (recover real opcode from the VM handler)
 * ============================================================
 * ionCube's VM stores a permuted value in opline->opcode and dispatches via the
 * opline->handler. Some snapshots already point at normal php8.dll VM handlers;
 * others still point at ionCube loader handlers. Resolve both forms from the
 * handler instead of trusting the permuted opcode byte. */
ZEND_API void ZEND_FASTCALL zend_vm_set_opcode_handler(zend_op *op);

#ifdef PHP_WIN32
#define IC_HANDLER_OPCODE_CACHE_SIZE 4096u
typedef struct _ic_handler_opcode_cache_entry {
	uintptr_t handler;
	zend_uchar op1_type;
	zend_uchar op2_type;
	zend_uchar result_type;
	zend_uchar opcode;
	uint32_t valid;
} ic_handler_opcode_cache_entry;
static ic_handler_opcode_cache_entry ic_handler_opcode_cache[IC_HANDLER_OPCODE_CACHE_SIZE];

static uint32_t ic_handler_opcode_cache_hash(uintptr_t handler,
                                             zend_uchar op1_type,
                                             zend_uchar op2_type,
                                             zend_uchar result_type)
{
	uintptr_t v = (handler >> 4) ^ ((uintptr_t)op1_type << 3) ^
	              ((uintptr_t)op2_type << 7) ^ ((uintptr_t)result_type << 11);
	return (uint32_t)((v * 2654435761u) & (IC_HANDLER_OPCODE_CACHE_SIZE - 1u));
}

static int ic_handler_opcode_cache_get(uintptr_t handler,
                                       zend_uchar op1_type,
                                       zend_uchar op2_type,
                                       zend_uchar result_type,
                                       zend_uchar *opcode_out)
{
	uint32_t idx = ic_handler_opcode_cache_hash(handler, op1_type, op2_type, result_type);
	uint32_t n;
	for (n = 0; n < IC_HANDLER_OPCODE_CACHE_SIZE; ++n) {
		ic_handler_opcode_cache_entry *entry =
		    &ic_handler_opcode_cache[(idx + n) & (IC_HANDLER_OPCODE_CACHE_SIZE - 1u)];
		if (!entry->valid) return 0;
		if (entry->handler == handler &&
		    entry->op1_type == op1_type &&
		    entry->op2_type == op2_type &&
		    entry->result_type == result_type) {
			if (opcode_out) *opcode_out = entry->opcode;
			return 1;
		}
	}
	return 0;
}

static void ic_handler_opcode_cache_put(uintptr_t handler,
                                        zend_uchar op1_type,
                                        zend_uchar op2_type,
                                        zend_uchar result_type,
                                        zend_uchar opcode)
{
	uint32_t idx = ic_handler_opcode_cache_hash(handler, op1_type, op2_type, result_type);
	uint32_t n;
	for (n = 0; n < IC_HANDLER_OPCODE_CACHE_SIZE; ++n) {
		ic_handler_opcode_cache_entry *entry =
		    &ic_handler_opcode_cache[(idx + n) & (IC_HANDLER_OPCODE_CACHE_SIZE - 1u)];
		if (!entry->valid ||
		    (entry->handler == handler &&
		     entry->op1_type == op1_type &&
		     entry->op2_type == op2_type &&
		     entry->result_type == result_type)) {
			entry->handler = handler;
			entry->op1_type = op1_type;
			entry->op2_type = op2_type;
			entry->result_type = result_type;
			entry->opcode = opcode;
			entry->valid = 1;
			return;
		}
	}
}

static int ic_loader_handler_opcode_from_opline(const zend_op_array *op_array,
                                                const zend_op *opline,
                                                zend_uchar *opcode_out);

static int zend_vm_handler_opcode_from_opline(const zend_op_array *op_array,
                                              const zend_op *opline,
                                              zend_uchar *opcode_out)
{
	uintptr_t handler;
	uint32_t opcode;

	if (!opline || !opline->handler) return 0;
	if (opline->opcode == ZEND_OP_DATA) return 0;

	handler = (uintptr_t)opline->handler;
	if (ic_handler_opcode_cache_get(handler, opline->op1_type,
	                                opline->op2_type, opline->result_type,
	                                opcode_out)) {
		return 1;
	}

	for (opcode = 0; opcode <= 255u; ++opcode) {
		zend_op probe_buf[2];
		zend_op *probe = &probe_buf[0];
		int matched = 0;

		if (opcode == ZEND_OP_DATA) continue;
		if (zend_get_opcode_name((zend_uchar)opcode) == NULL) continue;

		__try {
			dasm_copy_zend_op_safe(&probe_buf[0], opline);
			memset(&probe_buf[1], 0, sizeof(probe_buf[1]));
			if (op_array && op_array->opcodes &&
			    opline >= op_array->opcodes &&
			    opline + 1 < op_array->opcodes + op_array->last) {
				dasm_copy_zend_op_safe(&probe_buf[1], opline + 1);
			}
			probe->handler = NULL;
			probe->opcode = (zend_uchar)opcode;
			zend_vm_set_opcode_handler(probe);
			matched = ((uintptr_t)probe->handler == handler);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			matched = 0;
		}

		if (matched) {
			ic_handler_opcode_cache_put(handler, opline->op1_type,
			                            opline->op2_type, opline->result_type,
			                            (zend_uchar)opcode);
			if (opcode_out) *opcode_out = (zend_uchar)opcode;
			return 1;
		}
	}

	return 0;
}

static int zend_opcode_consumes_op_data(zend_uchar opcode)
{
	switch (opcode) {
		case ZEND_ASSIGN_DIM:
		case ZEND_ASSIGN_OBJ:
		case ZEND_ASSIGN_STATIC_PROP:
		case ZEND_ASSIGN_DIM_OP:
		case ZEND_ASSIGN_OBJ_OP:
		case ZEND_ASSIGN_STATIC_PROP_OP:
		case ZEND_ASSIGN_OBJ_REF:
		case ZEND_ASSIGN_STATIC_PROP_REF:
			return 1;
		default:
			return 0;
	}
}

static int zend_opline_is_op_data_pseudo(const zend_op_array *op_array, const zend_op *opline)
{
	const zend_op *prev;
	zend_uchar prev_opcode = 0;
	int have_prev_opcode = 0;

	if (!op_array || !opline || !op_array->opcodes) return 0;
	if (opline->opcode != ZEND_OP_DATA) return 0;
	if (opline->op2_type != IS_UNUSED || opline->result_type != IS_UNUSED) return 0;
	if (opline->op1_type != IS_CONST &&
	    opline->op1_type != IS_TMP_VAR &&
	    opline->op1_type != IS_VAR &&
	    opline->op1_type != IS_CV) {
		return 0;
	}
	if (opline <= op_array->opcodes || opline >= op_array->opcodes + op_array->last) return 0;

	prev = opline - 1;
	__try {
		have_prev_opcode = zend_vm_handler_opcode_from_opline(op_array, prev, &prev_opcode);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		have_prev_opcode = 0;
	}
	if (!have_prev_opcode) {
		__try {
			have_prev_opcode = ic_loader_handler_opcode_from_opline(op_array, prev, &prev_opcode);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			have_prev_opcode = 0;
		}
	}
	if (have_prev_opcode && zend_opcode_consumes_op_data(prev_opcode)) return 1;
	if (zend_opcode_consumes_op_data(prev->opcode)) return 1;
	return 0;
}

static int ic_loader_handler_opcode_from_opline(const zend_op_array *op_array,
                                                const zend_op *opline,
                                                zend_uchar *opcode_out)
{
	typedef int (__fastcall *ic_opcode_setter_fn)(zend_op *opline, unsigned char opcode);
	static const unsigned char setter_sig[] = { 0x0F, 0xB6, 0xC2, 0x56, 0x57 };
	static int setter_checked = 0;
	static int setter_available = 0;
	HMODULE hLoader;
	uintptr_t loader_base;
	uintptr_t handler;
	ic_opcode_setter_fn setter;
	uint32_t opcode;

	if (!opline || !opline->handler) return 0;
	if (opline->opcode == ZEND_OP_DATA) return 0;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;
	loader_base = (uintptr_t)hLoader;
	handler = (uintptr_t)opline->handler;
	if (handler < loader_base || handler >= loader_base + 0x300000u) return 0;

	if (ic_handler_opcode_cache_get(handler, opline->op1_type,
	                                opline->op2_type, opline->result_type,
	                                opcode_out)) {
		return 1;
	}

	if (!setter_checked) {
		setter_available = opcodedump_opcode_setter_hook_installed ||
		                   opcodedump_loader_bytes_match_mask(IC_OPCODE_SETTER_RVA,
		                                                      setter_sig, "xxxxx",
		                                                      sizeof(setter_sig));
		setter_checked = 1;
	}
	if (!setter_available) return 0;

	setter = (ic_opcode_setter_fn)(loader_base + IC_OPCODE_SETTER_RVA);
	for (opcode = 0; opcode <= 255u; ++opcode) {
		zend_op probe_buf[2];
		zend_op *probe = &probe_buf[0];
		int matched = 0;
		if (opcode == ZEND_OP_DATA) continue;
		__try {
			dasm_copy_zend_op_safe(&probe_buf[0], opline);
			memset(&probe_buf[1], 0, sizeof(probe_buf[1]));
			if (op_array && op_array->opcodes &&
			    opline >= op_array->opcodes &&
			    opline + 1 < op_array->opcodes + op_array->last) {
				dasm_copy_zend_op_safe(&probe_buf[1], opline + 1);
			}
			probe->handler = NULL;
			probe->opcode = (zend_uchar)opcode;
			(void)setter(probe, (unsigned char)opcode);
			matched = ((uintptr_t)probe->handler == handler);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			matched = 0;
		}
		if (matched) {
			ic_handler_opcode_cache_put(handler, opline->op1_type,
			                            opline->op2_type, opline->result_type,
			                            (zend_uchar)opcode);
			if (opcode_out) *opcode_out = (zend_uchar)opcode;
			return 1;
		}
	}

	return 0;
}
#endif


static zend_uchar dasm_ic_display_opcode(const zend_op_array *op_array, const zend_op *opline,
                                          zend_uchar opcode)
{
	zend_uchar decoded = opcode;
	/* PHP 8.1 / loader v15.5: ionCube's VM dispatches via the (decrypted) handler
	 * and stores a PERMUTED value in opline->opcode. When the snapshot has
	 * recovered the real php8.dll handler, map it back to the true opcode. This
	 * also works for naturally-plaintext op_arrays (e.g. {main}). */
	(void)op_array;
	if (opline) {
		zend_uchar real_op;
		int hit = 0;
		__try {
			if (zend_opline_is_op_data_pseudo(op_array, opline)) return ZEND_OP_DATA;
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		__try {
			hit = opcodedump_lookup_captured_opcode(opline, &real_op);
		} __except(EXCEPTION_EXECUTE_HANDLER) { hit = 0; }
		if (hit) return real_op;
		__try {
			hit = zend_vm_handler_opcode_from_opline(op_array, opline, &real_op);
		} __except(EXCEPTION_EXECUTE_HANDLER) { hit = 0; }
		if (hit) return real_op;
		__try {
			hit = ic_loader_handler_opcode_from_opline(op_array, opline, &real_op);
		} __except(EXCEPTION_EXECUTE_HANDLER) { hit = 0; }
		if (hit) return real_op;
	}
	return decoded;
}

#ifdef _M_IX86


static int ic_opcode_uses_loader_jump_materializer(zend_uchar opcode)
{
	return opcode == ZEND_JMP ||
	       opcode == ZEND_JMPZ ||
	       opcode == ZEND_JMPNZ ||
	       opcode == ZEND_JMPZNZ ||
	       opcode == ZEND_JMPZ_EX ||
	       opcode == ZEND_JMPNZ_EX ||
	       opcode == ZEND_JMP_SET;
}

#endif /* _M_IX86 */
#else
static zend_uchar dasm_ic_display_opcode(const zend_op_array *op_array, const zend_op *opline,
                                          zend_uchar opcode)
{
	return opcode;
}
#endif /* PHP_WIN32 */

static int dasm_result_has_resolved_function_name(zval *dst)
{
	return dst && Z_TYPE_P(dst) == IS_ARRAY &&
	       zend_hash_str_exists(Z_ARRVAL_P(dst), "resolved_function_name", sizeof("resolved_function_name") - 1);
}

static int dasm_result_has_concrete_resolved_function_name(zval *dst)
{
	zval *name_zv;
	zend_string *name;

	if (!dasm_result_has_resolved_function_name(dst)) return 0;
	name_zv = zend_hash_str_find(Z_ARRVAL_P(dst), "resolved_function_name", sizeof("resolved_function_name") - 1);
	if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) return 0;
	name = Z_STR_P(name_zv);
	if (!name || ZSTR_LEN(name) == 0) return 0;
	if (ZSTR_LEN(name) == sizeof("[obfuscated]") - 1 &&
	    memcmp(ZSTR_VAL(name), "[obfuscated]", sizeof("[obfuscated]") - 1) == 0) {
		return 0;
	}
	if (ZSTR_LEN(name) >= sizeof("_obf_") - 1 &&
	    memcmp(ZSTR_VAL(name), "_obf_", sizeof("_obf_") - 1) == 0) {
		return 0;
	}
	return 1;
}

static int dasm_zend_function_name_is_safe(zend_function *fbc)
{
	if (!fbc) return 0;
#ifdef PHP_WIN32
	__try {
		if (!dasm_ic_committed_readable_ptr(fbc)) return 0;
		if (!fbc->common.function_name ||
		    !dasm_ic_committed_readable_ptr(fbc->common.function_name)) return 0;
		if (ZSTR_LEN(fbc->common.function_name) == 0 ||
		    ZSTR_LEN(fbc->common.function_name) > 512) return 0;
		if (!dasm_ic_committed_readable_ptr(ZSTR_VAL(fbc->common.function_name))) return 0;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
#else
	if (!fbc->common.function_name) return 0;
#endif
	return 1;
}

static void dasm_add_resolved_function_name_from_fbc(zval *dst, zend_function *fbc, const char *source)
{
	if (!dst || !source || dasm_result_has_concrete_resolved_function_name(dst)) return;
	if (!dasm_zend_function_name_is_safe(fbc)) return;
#ifdef PHP_WIN32
	__try {
#endif
		add_assoc_stringl(dst, "resolved_function_name",
		                  ZSTR_VAL(fbc->common.function_name),
		                  ZSTR_LEN(fbc->common.function_name));
		add_assoc_string(dst, "resolved_function_name_source", (char *)source);
		add_assoc_long(dst, "resolved_function_type", (zend_long)fbc->type);
#ifdef PHP_WIN32
	} __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif
}

static void dasm_add_resolved_function_name(zval *dst, const zend_op_array *op_array,
                                            const zend_op *src, zend_uchar opcode,
                                            zend_long op2_constant)
{
	if (!dst || !op_array || !src) return;
	if (opcode != ZEND_INIT_FCALL && opcode != ZEND_INIT_FCALL_BY_NAME) return;

#ifdef PHP_WIN32
	__try {
#endif
		void **rtc = RUN_TIME_CACHE(op_array);
		if (rtc && op_array->cache_size > 0 &&
		    src->result.num >= 0 &&
		    (zend_long)src->result.num + (zend_long)sizeof(void *) <= (zend_long)op_array->cache_size) {
			zend_function *fbc = *(zend_function **)((char *)rtc + src->result.num);
			dasm_add_resolved_function_name_from_fbc(dst, fbc, "run_time_cache");
			if (dasm_result_has_concrete_resolved_function_name(dst)) return;
		}
#ifdef PHP_WIN32
	} __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif

#ifdef PHP_WIN32
	__try {
#endif
		zval *func = NULL;
		zval *name_zv = NULL;
		zend_function *fbc = NULL;
		if (!EG(function_table) || !op_array->literals) return;
		if (opcode == ZEND_INIT_FCALL_BY_NAME) {
			if (op2_constant < 0 || (uint32_t)(op2_constant + 1) >= (uint32_t)op_array->last_literal) return;
			name_zv = &op_array->literals[op2_constant + 1];
		} else {
			if (op2_constant < 0 || (uint32_t)op2_constant >= (uint32_t)op_array->last_literal) return;
			name_zv = &op_array->literals[op2_constant];
		}
		if (!name_zv || Z_TYPE_P(name_zv) != IS_STRING) return;
		func = zend_hash_find_ex(EG(function_table), Z_STR_P(name_zv), 1);
		if (!func) return;
		fbc = Z_FUNC_P(func);
		dasm_add_resolved_function_name_from_fbc(dst, fbc, "function_table");
#ifdef PHP_WIN32
	} __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif
}

/* ============================================================
 * dasm_zend_op
 * ============================================================ */
static void inline dasm_zend_op(zval *dst, const zend_op_array *op_array, const zend_op *src)
{
	const zend_op *raw_src;
	zend_op decoded_src;
	const char *op1_type_name, *op2_type_name, *result_type_name;
	zend_long op1_constant, op2_constant, result_constant;
	zend_long op1_value, op2_value, result_value;
	zend_uchar display_opcode;
	zend_uchar raw_opcode;
	zend_uchar ic_key_byte = 0;
	uint32_t ic_key_dword = 0;
	uint32_t ic_meta_flags = 0;
	uint8_t ic_operand_flags = 0;
	int have_ic_key_material = 0;
	int have_ic_meta_flags = 0;
	int have_ic_operand_flags = 0;
#ifdef PHP_WIN32
	int have_zend_op_data_pseudo = 0;
	int have_zend_handler_opcode = 0;
	zend_uchar zend_handler_opcode = 0;
	int have_ic_captured_opcode = 0;
	zend_uchar ic_captured_opcode = 0;
	int have_ic_handler_opcode = 0;
	zend_uchar ic_handler_opcode = 0;
#endif

	raw_src        = src;
	raw_opcode     = src ? src->opcode : 0;
	ic_decode_seh_phase = 1;
#ifdef PHP_WIN32
	__try {
		have_zend_op_data_pseudo = zend_opline_is_op_data_pseudo(op_array, src);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		have_zend_op_data_pseudo = 0;
	}
	if (have_zend_op_data_pseudo) {
		display_opcode = ZEND_OP_DATA;
	} else {
		__try {
			have_ic_captured_opcode = opcodedump_lookup_captured_opcode(src, &ic_captured_opcode);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			have_ic_captured_opcode = 0;
		}
		if (have_ic_captured_opcode) {
			display_opcode = ic_captured_opcode;
		} else {
			__try {
				have_zend_handler_opcode =
				    zend_vm_handler_opcode_from_opline(op_array, src, &zend_handler_opcode);
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				have_zend_handler_opcode = 0;
			}
			if (have_zend_handler_opcode) {
				display_opcode = zend_handler_opcode;
			} else {
				__try {
					have_ic_handler_opcode =
					    ic_loader_handler_opcode_from_opline(op_array, src, &ic_handler_opcode);
				} __except(EXCEPTION_EXECUTE_HANDLER) {
					have_ic_handler_opcode = 0;
				}
				display_opcode = have_ic_handler_opcode
				    ? ic_handler_opcode
				    : dasm_ic_display_opcode(op_array, src, src->opcode);
			}
		}
	}
#else
	display_opcode = dasm_ic_display_opcode(op_array, src, src->opcode);
#endif
#ifdef PHP_WIN32
	__try {
		if (op_array && src && op_array->opcodes) {
			zend_long op_index = (zend_long)(src - op_array->opcodes);
			have_ic_key_material = dasm_ic_key_material_for_index(op_array, op_index, &ic_key_byte, &ic_key_dword);
			{
				const uint32_t *desc = (const uint32_t *)ic_lookup_desc(op_array);
				if (dasm_ic_committed_readable_ptr(desc) &&
				    dasm_ic_committed_readable_ptr((const void *)(uintptr_t)desc[21]) &&
				    dasm_ic_committed_readable_ptr((const char *)(uintptr_t)desc[21] + 112)) {
					ic_meta_flags = *(const uint32_t *)((const char *)(uintptr_t)desc[21] + 112);
					have_ic_meta_flags = 1;
				}
				if (dasm_ic_committed_readable_ptr(desc) &&
				    (ic_meta_flags & 0x400u) != 0 &&
				    desc[4] &&
				    dasm_ic_committed_readable_ptr((const void *)(uintptr_t)desc[4]) &&
				    dasm_ic_committed_readable_ptr((const uint8_t *)(uintptr_t)desc[4] + op_index)) {
					ic_operand_flags = *((const uint8_t *)(uintptr_t)desc[4] + op_index);
					have_ic_operand_flags = 1;
				}
			}
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		have_ic_key_material = 0;
		ic_key_byte = 0;
		ic_key_dword = 0;
		have_ic_meta_flags = 0;
		have_ic_operand_flags = 0;
		ic_meta_flags = 0;
		ic_operand_flags = 0;
	}
#endif
	ic_decode_seh_phase = 3;
#ifdef PHP_WIN32
	dasm_copy_zend_op_safe(&decoded_src, src);
#else
	decoded_src    = *src;
#endif
	decoded_src.opcode = display_opcode;
	src = &decoded_src;

	ic_decode_seh_phase = 4;
	op1_type_name    = dasm_znode_type_name(src->op1_type);
	op2_type_name    = dasm_znode_type_name(src->op2_type);
	result_type_name = dasm_znode_type_name(src->result_type);

	ic_decode_seh_phase = 5;
	op1_constant    = src->op1.constant;
	op2_constant    = src->op2.constant;
	result_constant = src->result.constant;

	ic_decode_seh_phase = 6;
	if (src->op1_type == IS_CONST) {
		zend_long li = dasm_literal_index(op_array, src->op1.zv);
		if (li >= 0) op1_constant = li;
	}
	if (src->op2_type == IS_CONST) {
		zend_long li = dasm_literal_index(op_array, src->op2.zv);
		if (li >= 0) op2_constant = li;
	}
	if (src->result_type == IS_CONST) {
		zend_long li = dasm_literal_index(op_array, src->result.zv);
		if (li >= 0) result_constant = li;
	}

	ic_decode_seh_phase = 7;
	add_assoc_long_ex(dst, ("opcode"),         (sizeof("opcode")),         display_opcode);
	add_assoc_long_ex(dst, ("opcode_raw"),     (sizeof("opcode_raw")),     raw_opcode);
	add_assoc_long_ex(dst, ("opcode_xor_decoded"), (sizeof("opcode_xor_decoded")), display_opcode);
	if (have_ic_key_material) {
		add_assoc_long_ex(dst, ("ic_key_byte"),  (sizeof("ic_key_byte")),  (zend_long)ic_key_byte);
		add_assoc_long_ex(dst, ("ic_key_dword"), (sizeof("ic_key_dword")), (zend_long)ic_key_dword);
	}
	if (have_ic_meta_flags) {
		add_assoc_long_ex(dst, ("ic_meta_flags"), (sizeof("ic_meta_flags")), (zend_long)ic_meta_flags);
	}
	if (have_ic_operand_flags) {
		add_assoc_long_ex(dst, ("ic_operand_flags"), (sizeof("ic_operand_flags")), (zend_long)ic_operand_flags);
	}
	add_assoc_long_ex(dst, ("resolved_opcode"), (sizeof("resolved_opcode")), display_opcode);
	if (zend_get_opcode_name(display_opcode) != NULL) {
		add_assoc_string_ex(dst, "resolved_opcode_name", sizeof("resolved_opcode_name"), (char *)zend_get_opcode_name(display_opcode));
		add_assoc_string_ex(dst, "resolved_opcode_source", sizeof("resolved_opcode_source"),
#ifdef PHP_WIN32
		                    have_zend_op_data_pseudo ? "zend_op_data_pseudo" :
		                    have_ic_captured_opcode ? "ioncube_materializer_capture" :
		                    (have_zend_handler_opcode ? "zend_vm_handler" :
		                    (have_ic_handler_opcode ? "ioncube_loader_handler" :
#endif
		                    (have_ic_key_material ? "ioncube_xor_key" : "zend_opcode")
#ifdef PHP_WIN32
		                    ))
#endif
		                    );
	}
	add_assoc_long_ex(dst, ("op1_type"),        (sizeof("op1_type")),        src->op1_type);
	add_assoc_long_ex(dst, ("op2_type"),        (sizeof("op2_type")),        src->op2_type);
	add_assoc_long_ex(dst, ("result_type"),     (sizeof("result_type")),     src->result_type);
	add_assoc_long_ex(dst, ("extended_value"),  (sizeof("extended_value")),  src->extended_value);
	/* Mask ionCube-injected bits from lineno (same mask as line_start/line_end) */
	add_assoc_long_ex(dst, ("lineno"),          (sizeof("lineno")),          src->lineno & ~0x600000u);

#ifdef PHP_WIN32
	/* Fast path for JMP-class opcodes: skip the generic literal/CV-name paths that
	 * may crash under ionCube memory protection.  All operands are read directly. */
	if (ic_opcode_uses_loader_jump_materializer(display_opcode)) {
		zend_long op1_val, op2_val, res_val;
		ic_decode_seh_phase = 8;
		if (zend_get_opcode_name(display_opcode) != NULL)
			add_assoc_string(dst, "opcode_name", (char *)zend_get_opcode_name(display_opcode));
		if (op1_type_name)    add_assoc_string(dst, "op1_type_name",    (char *)op1_type_name);
		if (op2_type_name)    add_assoc_string(dst, "op2_type_name",    (char *)op2_type_name);
		if (result_type_name) add_assoc_string(dst, "result_type_name", (char *)result_type_name);
		ic_decode_seh_phase = 11;
		res_val = dasm_operand_value_safe(op_array, raw_src, display_opcode, 3, src->result_type, src->result, result_constant,
			dasm_operand_is_effective_jump_target(src, display_opcode, 3) ? -1 : (zend_long)src->result.var);
		op1_val = dasm_operand_value_safe(op_array, raw_src, display_opcode, 1, src->op1_type,    src->op1,    op1_constant,
			dasm_operand_is_effective_jump_target(src, display_opcode, 1) ? -1 : (zend_long)src->op1.var);
		op2_val = dasm_operand_value_safe(op_array, raw_src, display_opcode, 2, src->op2_type,    src->op2,    op2_constant,
			dasm_operand_is_effective_jump_target(src, display_opcode, 2) ? -1 : (zend_long)src->op2.var);
		ic_decode_seh_phase = 12;
		add_assoc_long_ex(dst, ("result.constant"),  (sizeof("result.constant")),  res_val);
		add_assoc_long_ex(dst, ("result.var"),        (sizeof("result.var")),        res_val);
		add_assoc_long_ex(dst, ("result.num"),        (sizeof("result.num")),        res_val);
		add_assoc_long_ex(dst, ("result.opline_num"), (sizeof("result.opline_num")), res_val);
		add_assoc_long_ex(dst, ("op1.constant"),      (sizeof("op1.constant")),      op1_val);
		add_assoc_long_ex(dst, ("op1.var"),           (sizeof("op1.var")),           op1_val);
		add_assoc_long_ex(dst, ("op1.num"),           (sizeof("op1.num")),           op1_val);
		add_assoc_long_ex(dst, ("op1.opline_num"),    (sizeof("op1.opline_num")),    op1_val);
		add_assoc_long_ex(dst, ("op2.constant"),      (sizeof("op2.constant")),      op2_val);
		add_assoc_long_ex(dst, ("op2.var"),           (sizeof("op2.var")),           op2_val);
		add_assoc_long_ex(dst, ("op2.num"),           (sizeof("op2.num")),           op2_val);
		add_assoc_long_ex(dst, ("op2.opline_num"),    (sizeof("op2.opline_num")),    op2_val);
		add_assoc_long(dst, "handler", (zend_long)(uintptr_t)src->handler);
		dasm_add_handler_rva(dst, raw_src);
		ic_decode_seh_phase = 10;
		__try { dasm_add_cv_name(dst, "op1.cv_name",    op_array, src->op1_type,    src->op1); } __except(EXCEPTION_EXECUTE_HANDLER) {}
		__try { dasm_add_cv_name(dst, "result.cv_name", op_array, src->result_type, src->result); } __except(EXCEPTION_EXECUTE_HANDLER) {}
		if (display_opcode == ZEND_JMPZNZ) {
			ic_decode_seh_phase = 14;
			zend_long ev_index = dasm_index_from_address_base(
				(uintptr_t)(uint32_t)raw_src->extended_value,
				(uintptr_t)op_array->opcodes, op_array->last);
			add_assoc_long(dst, "jmpznz_true_opline", ev_index);
		}
		return;
	}
#endif

	ic_decode_seh_phase = 8;
	if (zend_get_opcode_name(display_opcode) != NULL) {
		add_assoc_string(dst, "opcode_name", (char *)zend_get_opcode_name(display_opcode));
	}
	if (op1_type_name)    add_assoc_string(dst, "op1_type_name",    (char *)op1_type_name);
	if (op2_type_name)    add_assoc_string(dst, "op2_type_name",    (char *)op2_type_name);
	if (result_type_name) add_assoc_string(dst, "result_type_name", (char *)result_type_name);

#ifdef PHP_WIN32
	ic_decode_seh_phase = 9;
	__try { dasm_add_literal(dst, "op1.literal",    op_array, src->op1_type,    src->op1); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dasm_add_literal(dst, "op2.literal",    op_array, src->op2_type,    src->op2); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dasm_add_literal(dst, "result.literal", op_array, src->result_type, src->result); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
	dasm_add_literal(dst, "op1.literal",    op_array, src->op1_type,    src->op1);
	dasm_add_literal(dst, "op2.literal",    op_array, src->op2_type,    src->op2);
	dasm_add_literal(dst, "result.literal", op_array, src->result_type, src->result);
#endif

#ifdef PHP_WIN32
	ic_decode_seh_phase = 10;
	__try { dasm_add_cv_name(dst, "op1.cv_name",    op_array, src->op1_type,    src->op1); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dasm_add_cv_name(dst, "op2.cv_name",    op_array, src->op2_type,    src->op2); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { dasm_add_cv_name(dst, "result.cv_name", op_array, src->result_type, src->result); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
	dasm_add_cv_name(dst, "op1.cv_name",    op_array, src->op1_type,    src->op1);
	dasm_add_cv_name(dst, "op2.cv_name",    op_array, src->op2_type,    src->op2);
	dasm_add_cv_name(dst, "result.cv_name", op_array, src->result_type, src->result);
#endif

	ic_decode_seh_phase = 11;
#ifdef PHP_WIN32
	result_value = dasm_operand_value_safe(op_array, raw_src, src->opcode, 3, src->result_type, src->result, result_constant,
		dasm_operand_is_effective_jump_target(src, src->opcode, 3) ? -1 : (zend_long)src->result.var);
	op1_value    = dasm_operand_value_safe(op_array, raw_src, src->opcode, 1, src->op1_type,    src->op1,    op1_constant,
		dasm_operand_is_effective_jump_target(src, src->opcode, 1) ? -1 : (zend_long)src->op1.var);
	op2_value    = dasm_operand_value_safe(op_array, raw_src, src->opcode, 2, src->op2_type,    src->op2,    op2_constant,
		dasm_operand_is_effective_jump_target(src, src->opcode, 2) ? -1 : (zend_long)src->op2.var);
#else
	result_value = dasm_operand_value(op_array, raw_src, src->opcode, 3, src->result_type, src->result, result_constant);
	op1_value    = dasm_operand_value(op_array, raw_src, src->opcode, 1, src->op1_type,    src->op1,    op1_constant);
	op2_value    = dasm_operand_value(op_array, raw_src, src->opcode, 2, src->op2_type,    src->op2,    op2_constant);
#endif

	ic_decode_seh_phase = 12;
	add_assoc_long_ex(dst, ("result.constant"),   (sizeof("result.constant")),   result_value);
	add_assoc_long_ex(dst, ("result.var"),         (sizeof("result.var")),         result_value);
	add_assoc_long_ex(dst, ("result.num"),         (sizeof("result.num")),         result_value);
	add_assoc_long_ex(dst, ("result.opline_num"),  (sizeof("result.opline_num")),  result_value);
	add_assoc_long_ex(dst, ("op1.constant"),       (sizeof("op1.constant")),       op1_value);
	add_assoc_long_ex(dst, ("op1.var"),            (sizeof("op1.var")),            op1_value);
	add_assoc_long_ex(dst, ("op1.num"),            (sizeof("op1.num")),            op1_value);
	add_assoc_long_ex(dst, ("op1.opline_num"),     (sizeof("op1.opline_num")),     op1_value);
	add_assoc_long_ex(dst, ("op2.constant"),       (sizeof("op2.constant")),       op2_value);
	add_assoc_long_ex(dst, ("op2.var"),            (sizeof("op2.var")),            op2_value);
	add_assoc_long_ex(dst, ("op2.num"),            (sizeof("op2.num")),            op2_value);
	add_assoc_long_ex(dst, ("op2.opline_num"),     (sizeof("op2.opline_num")),     op2_value);
	ic_decode_seh_phase = 13;
	add_assoc_long(dst, "handler", (zend_long)(uintptr_t)src->handler);
#ifdef PHP_WIN32
	dasm_add_handler_rva(dst, raw_src);
	__try {
		dasm_add_resolved_function_name(dst, op_array, raw_src, display_opcode, op2_constant);
	} __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
	dasm_add_resolved_function_name(dst, op_array, raw_src, display_opcode, op2_constant);
#endif

	/* ZEND_JMPZNZ: extended_value is the second jump target (non-zero/non-null branch).
	 * On 32-bit (ZEND_USE_ABS_JMP_ADDR=1): stored as absolute opline pointer cast to uint32_t.
	 * On 64-bit (ZEND_USE_ABS_JMP_ADDR=0): stored as relative byte offset from current opline. */
	if (display_opcode == ZEND_JMPZNZ) {
		zend_long ev_index = -1;
		ic_decode_seh_phase = 14;
#if ZEND_USE_ABS_JMP_ADDR
		ev_index = dasm_index_from_address_base(
			(uintptr_t)(uint32_t)raw_src->extended_value,
			(uintptr_t)op_array->opcodes, op_array->last);
#else
		{
			const zend_op *ev_target = (const zend_op *)((const char *)raw_src + (int32_t)raw_src->extended_value);
			if (op_array->opcodes && ev_target >= op_array->opcodes &&
			    ev_target < (op_array->opcodes + op_array->last)) {
				ev_index = (zend_long)(ev_target - op_array->opcodes);
			}
		}
#endif
		add_assoc_long(dst, "jmpznz_true_opline", ev_index);
	}

	/* FE_FETCH_R/RW keeps the foreach-done target in extended_value. op2 is
	 * the value destination, so exposing it as a CFG target creates bogus
	 * edges. */
	if (display_opcode == ZEND_FE_FETCH_R || display_opcode == ZEND_FE_FETCH_RW) {
		zend_long ev_index = -1;
		zend_long current_index = (op_array && op_array->opcodes && raw_src)
			? (zend_long)(raw_src - op_array->opcodes) : -1;
		ic_decode_seh_phase = 15;
#if ZEND_USE_ABS_JMP_ADDR
		ev_index = dasm_index_from_address_base(
			(uintptr_t)(uint32_t)raw_src->extended_value,
			(uintptr_t)op_array->opcodes, op_array->last);
#endif
		if (ev_index < 0 && current_index >= 0 &&
		    (raw_src->extended_value % sizeof(zend_op)) == 0) {
			zend_long rel = (zend_long)(raw_src->extended_value / sizeof(zend_op));
			zend_long candidate = current_index + rel;
			if (candidate >= 0 && candidate < (zend_long)op_array->last) {
				ev_index = candidate;
			}
		}
		add_assoc_long(dst, "fe_fetch_done_opline", ev_index);
	}
}

#ifdef PHP_WIN32
static int dasm_array_has_key(zval *arr, const char *key)
{
	size_t len;
	return arr && Z_TYPE_P(arr) == IS_ARRAY &&
	       ((len = strlen(key)),
	        zend_hash_str_exists(Z_ARRVAL_P(arr), key, len) ||
	        (len > 0 && zend_hash_str_exists(Z_ARRVAL_P(arr), key, len - 1)));
}

static void dasm_add_dynamic_long(zval *dst, const char *key, zend_long value)
{
	dasm_add_assoc_long_ex(dst, key, strlen(key) + 1, value);
}

static zend_uchar dasm_opcode_from_name(const char *name)
{
	if (name == NULL) return 0;
	if (strcmp(name, "ZEND_JMP") == 0) return ZEND_JMP;
	if (strcmp(name, "ZEND_FAST_CALL") == 0) return ZEND_FAST_CALL;
	if (strcmp(name, "ZEND_JMPZ") == 0) return ZEND_JMPZ;
	if (strcmp(name, "ZEND_JMPNZ") == 0) return ZEND_JMPNZ;
	if (strcmp(name, "ZEND_JMPZNZ") == 0) return ZEND_JMPZNZ;
	if (strcmp(name, "ZEND_JMPZ_EX") == 0) return ZEND_JMPZ_EX;
	if (strcmp(name, "ZEND_JMPNZ_EX") == 0) return ZEND_JMPNZ_EX;
	if (strcmp(name, "ZEND_FE_RESET_R") == 0) return ZEND_FE_RESET_R;
	if (strcmp(name, "ZEND_FE_RESET_RW") == 0) return ZEND_FE_RESET_RW;
	if (strcmp(name, "ZEND_JMP_SET") == 0) return ZEND_JMP_SET;
	if (strcmp(name, "ZEND_COALESCE") == 0) return ZEND_COALESCE;
	if (strcmp(name, "ZEND_ASSERT_CHECK") == 0) return ZEND_ASSERT_CHECK;
	if (strcmp(name, "ZEND_CATCH") == 0) return ZEND_CATCH;
	return 0;
}

static zend_uchar dasm_array_opcode_or_src(zval *arr, const zend_op *src)
{
	zval *zv;
	if (arr && Z_TYPE_P(arr) == IS_ARRAY) {
		zv = zend_hash_str_find(Z_ARRVAL_P(arr), "opcode", sizeof("opcode") - 1);
		if (zv && Z_TYPE_P(zv) == IS_LONG && Z_LVAL_P(zv) != 0) {
			return (zend_uchar)Z_LVAL_P(zv);
		}
		zv = zend_hash_str_find(Z_ARRVAL_P(arr), "opcode_name", sizeof("opcode_name") - 1);
		if (zv && Z_TYPE_P(zv) == IS_STRING) {
			zend_uchar opcode = dasm_opcode_from_name(Z_STRVAL_P(zv));
			if (opcode != 0) return opcode;
		}
	}
	return src ? src->opcode : 0;
}

static void dasm_add_jump_fallback_target(zval *dst, const zend_op_array *op_array,
                                          const zend_op *src, zend_uchar opcode)
{
	zend_long target = -1;
	int operand_index = 0;
	const char *prefix = NULL;

	if (op_array == NULL || src == NULL || op_array->opcodes == NULL) return;
	if (!dasm_operand_is_effective_jump_target(src, opcode,
	    (opcode == ZEND_JMP || opcode == ZEND_FAST_CALL) ? 1 : 2)) return;

	switch (opcode) {
		case ZEND_JMP:
		case ZEND_FAST_CALL:
			operand_index = 1;
			prefix = "op1";
			break;
		case ZEND_JMPZ:
		case ZEND_JMPNZ:
		case ZEND_JMPZNZ:
		case ZEND_JMPZ_EX:
		case ZEND_JMPNZ_EX:
		case ZEND_FE_RESET_R:
		case ZEND_FE_RESET_RW:
		case ZEND_JMP_SET:
		case ZEND_COALESCE:
		case ZEND_ASSERT_CHECK:
		case ZEND_CATCH:
			operand_index = 2;
			prefix = "op2";
			break;
		default:
			return;
	}

	__try {
		target = dasm_jump_target_index(op_array, src, opcode, operand_index,
			operand_index == 1 ? src->op1 : src->op2);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		target = -1;
	}

	if (target >= 0) {
		char key[32];
		snprintf(key, sizeof(key), "%s.constant", prefix);
		if (!dasm_array_has_key(dst, key)) dasm_add_dynamic_long(dst, key, target);
		snprintf(key, sizeof(key), "%s.var", prefix);
		if (!dasm_array_has_key(dst, key)) dasm_add_dynamic_long(dst, key, target);
		snprintf(key, sizeof(key), "%s.num", prefix);
		if (!dasm_array_has_key(dst, key)) dasm_add_dynamic_long(dst, key, target);
		snprintf(key, sizeof(key), "%s.opline_num", prefix);
		if (!dasm_array_has_key(dst, key)) dasm_add_dynamic_long(dst, key, target);
	}
}

static void inline dasm_zend_op_minimal(zval *dst, const zend_op_array *op_array, const zend_op *src)
{
	zend_uchar opcode = dasm_array_opcode_or_src(dst, src);
	if (src == NULL) return;

	__try { if (!dasm_array_has_key(dst, "opcode")) add_assoc_long_ex(dst, ("opcode"), (sizeof("opcode")), opcode); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "opcode_name") && zend_get_opcode_name(opcode) != NULL) add_assoc_string(dst, "opcode_name", (char *)zend_get_opcode_name(opcode)); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "op1_type")) add_assoc_long_ex(dst, ("op1_type"), (sizeof("op1_type")), src->op1_type); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "op2_type")) add_assoc_long_ex(dst, ("op2_type"), (sizeof("op2_type")), src->op2_type); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "result_type")) add_assoc_long_ex(dst, ("result_type"), (sizeof("result_type")), src->result_type); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "extended_value")) add_assoc_long_ex(dst, ("extended_value"), (sizeof("extended_value")), src->extended_value); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "lineno")) add_assoc_long_ex(dst, ("lineno"), (sizeof("lineno")), src->lineno & ~0x600000u); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { if (!dasm_array_has_key(dst, "handler")) add_assoc_long(dst, "handler", (zend_long)(uintptr_t)src->handler); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#ifdef PHP_WIN32
	__try { if (!dasm_array_has_key(dst, "handler_rva")) dasm_add_handler_rva(dst, src); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif
	__try { add_assoc_long(dst, "decode_phase", (zend_long)ic_decode_seh_phase); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { add_assoc_long(dst, "decode_exception_code", (zend_long)ic_decode_seh_code); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	__try { add_assoc_long(dst, "decode_index", ic_decode_seh_index); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	/* Capture condition operand (op1) for conditional jumps: main path may have
	 * crashed before setting these, but the raw opline bytes are readable. */
	if (opcode == ZEND_JMPZ || opcode == ZEND_JMPNZ ||
	    opcode == ZEND_JMPZ_EX || opcode == ZEND_JMPNZ_EX ||
	    opcode == ZEND_FE_RESET_R || opcode == ZEND_FE_RESET_RW ||
	    opcode == ZEND_JMP_SET || opcode == ZEND_COALESCE || opcode == ZEND_ASSERT_CHECK) {
		__try {
			if (!dasm_array_has_key(dst, "op1.constant")) dasm_add_dynamic_long(dst, "op1.constant", (zend_long)src->op1.constant);
			if (!dasm_array_has_key(dst, "op1.var"))      dasm_add_dynamic_long(dst, "op1.var",      (zend_long)src->op1.var);
			if (!dasm_array_has_key(dst, "op1.num"))      dasm_add_dynamic_long(dst, "op1.num",      (zend_long)src->op1.num);
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
		__try { dasm_add_cv_name(dst, "op1.cv_name", op_array, src->op1_type, src->op1); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	}
	__try { dasm_add_jump_fallback_target(dst, op_array, src, opcode); } __except(EXCEPTION_EXECUTE_HANDLER) {}
	add_assoc_bool(dst, "decode_failed", 1);
}
#endif

/* ============================================================
 * Live range
 * ============================================================ */
#if defined(ZEND_ENGINE_MODERN)
static void inline dasm_zend_live_range(zval *dst, const zend_live_range *src)
{
	add_assoc_long_ex(dst, ("var"),   (sizeof("var")),   src->var);
	add_assoc_long_ex(dst, ("start"), (sizeof("start")), src->start);
	add_assoc_long_ex(dst, ("end"),   (sizeof("end")),   src->end);
}
#endif

static void inline dasm_zend_try_catch_element(zval *dst, const zend_try_catch_element *src)
{
	add_assoc_long_ex(dst, ("try_op"),     (sizeof("try_op")),     src->try_op);
	add_assoc_long_ex(dst, ("catch_op"),   (sizeof("catch_op")),   src->catch_op);
	add_assoc_long_ex(dst, ("finally_op"), (sizeof("finally_op")), src->finally_op);
	add_assoc_long_ex(dst, ("finally_end"),(sizeof("finally_end")),src->finally_end);
}

static void inline dasm_HashTable(zval *dst, HashTable *src)
{
	zend_ulong num_key;
	zend_string *str_key;
	zval *val;
	ZEND_HASH_FOREACH_KEY_VAL(src, num_key, str_key, val) {
		zval zv;
		ZVAL_COPY_VALUE(&zv, val);
		if (str_key) {
			add_assoc_zval_ex(dst, ZSTR_VAL(str_key), ZSTR_LEN(str_key) + 1, &zv);
		} else {
			add_index_zval(dst, num_key, &zv);
		}
	} ZEND_HASH_FOREACH_END();
}

static void inline dasm_function_table(zval *dst, const HashTable *src)
{
	zend_function *zif;
	zend_ulong num_key;
	zend_string *str_key;
	ZEND_HASH_FOREACH_KEY_PTR((HashTable *)src, num_key, str_key, zif) {
		if (zif->common.type == ZEND_USER_FUNCTION) {
			zval zv, array;
			zend_op_array *op_array;
			array_init(&zv);
			add_assoc_long(&zv, "type", zif->type);
			op_array = &(zif->op_array);
#ifdef PHP_WIN32
			{
				ic_dynamic_saved_op_array *dynamic_saved =
				    ic_dynamic_find_saved_for_dump(op_array, str_key);
				if (dynamic_saved) {
					op_array = &dynamic_saved->copy;
				}
			}
#endif
#ifdef PHP_WIN32
			/* Contain any per-function serialization fault so one bad op_array
			 * cannot abort the whole dump. */
			__try { dasm_zend_op_array(&zv, op_array); }
			__except(EXCEPTION_EXECUTE_HANDLER) {}
#else
			dasm_zend_op_array(&zv, op_array);
#endif
			array_init(&array);
			if (str_key) {
				dasm_add_zend_string_and_hex(&array, "function_table_key",
				                             "function_table_key_hex", str_key);
			} else {
				add_assoc_long(&array, "function_table_key", (zend_long)num_key);
				add_assoc_null(&array, "function_table_key_hex");
			}
			add_assoc_zval(&array, "op_array", &zv);
			if (str_key) {
				add_assoc_zval_ex(dst, ZSTR_VAL(str_key), ZSTR_LEN(str_key) + 1, &array);
			} else {
				add_index_zval(dst, num_key, &array);
			}
		}
	} ZEND_HASH_FOREACH_END();
}

static void inline dasm_merge_extra_function_table(zval *dst)
{
	zend_string *key;
	zval *value;

	if (Z_TYPE(opcodedump_extra_function_table) != IS_ARRAY) return;
	ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL(opcodedump_extra_function_table), key, value) {
		zval copy;
		if (!key) continue;
		ZVAL_DUP(&copy, value);
		add_assoc_zval_ex(dst, ZSTR_VAL(key), ZSTR_LEN(key) + 1, &copy);
	} ZEND_HASH_FOREACH_END();
}

static void dasm_add_parent_op_array_info(zval *dst, const zend_op_array *parent)
{
	if (parent == NULL) {
		add_assoc_null(dst, "parent_function_name");
		add_assoc_null(dst, "parent_function_name_hex");
		add_assoc_null(dst, "parent_filename");
		add_assoc_null(dst, "parent_filename_hex");
		add_assoc_null(dst, "parent_scope");
		add_assoc_null(dst, "parent_scope_hex");
		return;
	}

	dasm_add_zend_string_and_hex(dst, "parent_function_name",
	                             "parent_function_name_hex", parent->function_name);
	dasm_add_zend_string_and_hex(dst, "parent_filename",
	                             "parent_filename_hex", parent->filename);
	if (parent->scope) {
		dasm_add_zend_string_and_hex(dst, "parent_scope",
		                             "parent_scope_hex", parent->scope->name);
	} else {
		add_assoc_null(dst, "parent_scope");
		add_assoc_null(dst, "parent_scope_hex");
	}
}

static void inline dasm_lambda_closures(zval *dst, const zend_op_array *parent)
{
	zval closures, report;
	uint32_t declared = 0;
	uint32_t dumped = 0;
	HashTable *function_table = CG(function_table) ? CG(function_table) : EG(function_table);
	int i;

	array_init(&closures);

	if (parent && parent->opcodes && parent->last > 0 && parent->last < 65536 &&
	    parent->literals && parent->last_literal > 0 && parent->last_literal < 65536) {
		for (i = 0; i < (int)parent->last; ++i) {
			const zend_op *opline = &(parent->opcodes[i]);
			zend_uchar opcode = dasm_ic_display_opcode(parent, opline, opline->opcode);
			zend_long literal_index = -1;
			zend_string *lambda_id = NULL;
			zval *zfunc = NULL;
			zend_function *func = NULL;
			zval entry;

			if (opcode != ZEND_DECLARE_LAMBDA_FUNCTION) {
				continue;
			}

			declared++;
			array_init(&entry);
			add_assoc_long(&entry, "opcode_index", (zend_long)i);
			add_assoc_long(&entry, "opcode", (zend_long)opcode);

			if (opline->op1_type == IS_CONST) {
				literal_index = dasm_literal_index(parent, opline->op1.zv);
			}
			add_assoc_long(&entry, "literal_index", literal_index);

			if (literal_index >= 0 && literal_index < (zend_long)parent->last_literal &&
			    Z_TYPE(parent->literals[literal_index]) == IS_STRING) {
				lambda_id = Z_STR(parent->literals[literal_index]);
				dasm_add_zend_string_and_hex(&entry, "lambda_id", "lambda_id_hex", lambda_id);
			} else {
				add_assoc_null(&entry, "lambda_id");
				add_assoc_null(&entry, "lambda_id_hex");
			}

			dasm_add_parent_op_array_info(&entry, parent);

			if (function_table && lambda_id) {
#ifdef PHP_WIN32
				__try {
					zfunc = zend_hash_find(function_table, lambda_id);
				} __except(EXCEPTION_EXECUTE_HANDLER) {
					zfunc = NULL;
				}
#else
				zfunc = zend_hash_find(function_table, lambda_id);
#endif
			}

			if (zfunc && Z_TYPE_P(zfunc) == IS_PTR) {
				func = (zend_function *)Z_PTR_P(zfunc);
			} else if (zfunc && Z_TYPE_P(zfunc) == IS_INDIRECT) {
				zval *indirect = Z_INDIRECT_P(zfunc);
				if (indirect && Z_TYPE_P(indirect) == IS_PTR) {
					func = (zend_function *)Z_PTR_P(indirect);
				}
			}

			if (func && func->type == ZEND_USER_FUNCTION) {
				zval op_array_dump;
				array_init(&op_array_dump);
#ifdef PHP_WIN32
				__try {
					dasm_zend_op_array(&op_array_dump, &(func->op_array));
					add_assoc_zval(&entry, "op_array", &op_array_dump);
					dumped++;
				} __except(EXCEPTION_EXECUTE_HANDLER) {
					zval_ptr_dtor(&op_array_dump);
					add_assoc_null(&entry, "op_array");
				}
#else
				dasm_zend_op_array(&op_array_dump, &(func->op_array));
				add_assoc_zval(&entry, "op_array", &op_array_dump);
				dumped++;
#endif
			} else {
				add_assoc_null(&entry, "op_array");
			}

			add_next_index_zval(&closures, &entry);
		}
	}

	array_init(&report);
	add_assoc_long(&report, "declared_lambdas", declared);
	add_assoc_long(&report, "dumped_closure_op_arrays", dumped);
	add_assoc_long(&report, "missing", declared >= dumped ? declared - dumped : 0);

	add_assoc_zval(dst, "closures", &closures);
	add_assoc_zval(dst, "closure_report", &report);
}

static void inline _dasm_properties_info(zval *dst, const zend_property_info *src)
{
	if (src->name == NULL) {
		add_assoc_null(dst, "name");
		add_assoc_long(dst, "name_len", 0);
	} else {
		add_assoc_string(dst, "name", ZSTR_VAL(src->name));
		add_assoc_long(dst, "name_len", ZSTR_LEN(src->name));
	}
	if (src->doc_comment == NULL) {
		add_assoc_null(dst, "doc_comment");
		add_assoc_long(dst, "doc_comment_len", 0);
	} else {
		add_assoc_string(dst, "doc_comment", ZSTR_VAL(src->doc_comment));
		add_assoc_long(dst, "doc_comment_len", ZSTR_LEN(src->doc_comment));
	}
	add_assoc_long(dst, "offset", src->offset);
	add_assoc_long(dst, "flags",  src->flags);
	if (src->ce && src->ce->name) {
		add_assoc_string(dst, "ce", ZSTR_VAL(src->ce->name));
	} else {
		add_assoc_null(dst, "ce");
	}
	/* PHP 8.x: typed properties — type is a zend_type struct. */
	add_assoc_long(dst, "prop_type", (zend_long)ZEND_TYPE_FULL_MASK(src->type));
	add_assoc_bool(dst, "prop_has_type", ZEND_TYPE_IS_SET(src->type) ? 1 : 0);
	if (ZEND_TYPE_HAS_NAME(src->type)) {
		zend_string *type_name = ZEND_TYPE_NAME(src->type);
		if (type_name) {
			add_assoc_string(dst, "prop_type_name", ZSTR_VAL(type_name));
		} else {
			add_assoc_null(dst, "prop_type_name");
		}
	} else if (ZEND_TYPE_IS_SET(src->type)) {
		add_assoc_long(dst, "prop_type_code", (zend_long)ZEND_TYPE_PURE_MASK(src->type));
	}
}

static void inline dasm_properties_info(zval *dst, zend_class_entry *ce, int statics)
{
	zend_property_info *prop_info;
	zend_string *key;
	ZEND_HASH_FOREACH_STR_KEY_PTR(&ce->properties_info, key, prop_info) {
		zval *prop = NULL;
		if (statics && (prop_info->flags & ZEND_ACC_STATIC) != 0) {
			prop = &ce->default_static_members_table[prop_info->offset];
		} else if (!statics && (prop_info->flags & ZEND_ACC_STATIC) == 0) {
			prop = &ce->default_properties_table[OBJ_PROP_TO_NUM(prop_info->offset)];
		}
		if (!prop) continue;
		zval zv;
		array_init(&zv);
		_dasm_properties_info(&zv, prop_info);

		/* Export the resolved default value — prop was computed but previously unused (bug). */
#ifdef PHP_WIN32
		__try {
			if (prop && Z_TYPE_P(prop) != IS_UNDEF) {
				zval prop_copy;
				ZVAL_COPY_VALUE(&prop_copy, prop);
				add_assoc_zval(&zv, "default_value", &prop_copy);
				add_assoc_bool(&zv, "has_default_value", 1);
			} else {
				add_assoc_null(&zv, "default_value");
				add_assoc_bool(&zv, "has_default_value", 0);
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			add_assoc_null(&zv, "default_value");
			add_assoc_bool(&zv, "has_default_value", 0);
		}
#else
		if (Z_TYPE_P(prop) != IS_UNDEF) {
			zval prop_copy;
			ZVAL_COPY_VALUE(&prop_copy, prop);
			add_assoc_zval(&zv, "default_value", &prop_copy);
			add_assoc_bool(&zv, "has_default_value", 1);
		} else {
			add_assoc_null(&zv, "default_value");
			add_assoc_bool(&zv, "has_default_value", 0);
		}
#endif
		add_assoc_zval_ex(dst, ZSTR_VAL(prop_info->name), ZSTR_LEN(prop_info->name) + 1, &zv);
	} ZEND_HASH_FOREACH_END();
}

/* Export class constants (name => {value, doc_comment, ce}) */
static void inline dasm_constants_table(zval *dst, zend_class_entry *ce)
{
	zend_string          *con_key;
	zend_class_constant  *c;
	if (!ce) return;
	ZEND_HASH_FOREACH_STR_KEY_PTR(&ce->constants_table, con_key, c) {
		zval zv, val_copy;
		if (!con_key || !c) continue;
#ifdef PHP_WIN32
		if (!dasm_ic_committed_readable_ptr(c)) continue;
#endif
		array_init(&zv);
		ZVAL_COPY_VALUE(&val_copy, &c->value);
		add_assoc_zval_ex(&zv, ("value"), (sizeof("value")), &val_copy);
		if (c->doc_comment
#ifdef PHP_WIN32
		    && dasm_ic_committed_readable_ptr(c->doc_comment)
#endif
		) {
			add_assoc_string(&zv, "doc_comment", ZSTR_VAL(c->doc_comment));
		} else {
			add_assoc_null(&zv, "doc_comment");
		}
		if (c->ce && c->ce->name
#ifdef PHP_WIN32
		    && dasm_ic_committed_readable_ptr(c->ce)
		    && dasm_ic_committed_readable_ptr(c->ce->name)
#endif
		) {
			add_assoc_string(&zv, "ce", ZSTR_VAL(c->ce->name));
		} else {
			add_assoc_null(&zv, "ce");
		}
		add_assoc_zval_ex(dst, ZSTR_VAL(con_key), ZSTR_LEN(con_key) + 1, &zv);
	} ZEND_HASH_FOREACH_END();
}

/* Export the list of interface names a class implements */
static void inline dasm_interfaces_list(zval *dst, zend_class_entry *ce)
{
	uint32_t i;
	if (!ce || !ce->interfaces || ce->num_interfaces == 0) return;
	for (i = 0; i < ce->num_interfaces; i++) {
		zend_class_entry *iface = ce->interfaces[i];
		if (!iface || !iface->name) continue;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(iface) &&
			    dasm_ic_committed_readable_ptr(iface->name)) {
				add_next_index_string(dst, ZSTR_VAL(iface->name));
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		add_next_index_string(dst, ZSTR_VAL(iface->name));
#endif
	}
}

/* Export the list of trait names used by a class */
static void inline dasm_traits_list(zval *dst, zend_class_entry *ce)
{
	uint32_t i;
	if (!ce || !ce->trait_names || ce->num_traits == 0) return;
	for (i = 0; i < ce->num_traits; i++) {
		zend_string *tname = ce->trait_names[i].name;
		if (!tname) continue;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(tname)) {
				add_next_index_string(dst, ZSTR_VAL(tname));
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		add_next_index_string(dst, ZSTR_VAL(tname));
#endif
	}
}

static void inline dasm_zend_class_entry(zval *dst, zend_class_entry *src)
{
	add_assoc_long_ex(dst, ("type"), (sizeof("type")), src->type);
	if (src->name == NULL) {
		add_assoc_null(dst, "name");
		add_assoc_long(dst, "name_len", 0);
	} else {
		add_assoc_string(dst, "name", ZSTR_VAL(src->name));
		add_assoc_long(dst, "name_len", ZSTR_LEN(src->name));
	}

	/* parent: may be unresolved/dangling if parent class wasn't found */
#ifdef PHP_WIN32
	{
		const char *_pname = NULL;
		size_t _pname_len = 0;
		__try {
			if (src->parent &&
			    dasm_ic_committed_readable_ptr(src->parent) &&
			    src->parent->name &&
			    dasm_ic_committed_readable_ptr(src->parent->name)) {
				_pname = ZSTR_VAL(src->parent->name);
				_pname_len = ZSTR_LEN(src->parent->name);
				if (_pname_len > 4096 ||
				    !dasm_ic_committed_readable_ptr(_pname) ||
				    !dasm_ic_committed_readable_ptr(_pname + _pname_len)) {
					_pname = NULL;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) { _pname = NULL; }
		if (_pname) {
			add_assoc_stringl(dst, "parent", (char *)_pname, _pname_len);
		} else {
			add_assoc_null_ex(dst, ("parent"), (sizeof("parent")));
		}
	}
#else
	if (src->parent) {
		add_assoc_string(dst, "parent", ZSTR_VAL(src->parent->name));
	} else {
		add_assoc_null_ex(dst, ("parent"), (sizeof("parent")));
	}
#endif

	add_assoc_long_ex(dst, ("refcount"),                    (sizeof("refcount")),                    src->refcount);
	add_assoc_long_ex(dst, ("ce_flags"),                    (sizeof("ce_flags")),                    src->ce_flags);
	add_assoc_long_ex(dst, ("default_properties_count"),    (sizeof("default_properties_count")),    src->default_properties_count);
	add_assoc_long_ex(dst, ("default_static_members_count"),(sizeof("default_static_members_count")),src->default_static_members_count);
	add_assoc_long_ex(dst, ("default_properties_table_addr"), (sizeof("default_properties_table_addr")), (zend_long)(uintptr_t)src->default_properties_table);
	add_assoc_long_ex(dst, ("default_static_members_table_addr"), (sizeof("default_static_members_table_addr")), (zend_long)(uintptr_t)src->default_static_members_table);

#ifdef PHP_WIN32
	if (src->default_properties_table
	    && src->default_properties_count > 0
	    && src->default_properties_count < 4096) {
		zval table;
		int i;
		array_init(&table);
		for (i = 0; i < src->default_properties_count; i++) {
			zval zv;
			__try { ZVAL_COPY_VALUE(&zv, src->default_properties_table + i); }
			__except(EXCEPTION_EXECUTE_HANDLER) { ZVAL_NULL(&zv); }
			add_next_index_zval(&table, &zv);
		}
		add_assoc_zval(dst, "default_properties_table", &table);
	} else {
		add_assoc_null_ex(dst, ("default_properties_table"), (sizeof("default_properties_table")));
	}
	if (src->default_static_members_table
	    && src->default_static_members_count > 0
	    && src->default_static_members_count < 4096) {
		zval table;
		int i;
		array_init(&table);
		for (i = 0; i < src->default_static_members_count; i++) {
			zval zv;
			__try { ZVAL_COPY_VALUE(&zv, src->default_static_members_table + i); }
			__except(EXCEPTION_EXECUTE_HANDLER) { ZVAL_NULL(&zv); }
			add_next_index_zval(&table, &zv);
		}
		add_assoc_zval(dst, "default_static_members_table", &table);
	} else {
		add_assoc_null_ex(dst, ("default_static_members_table"), (sizeof("default_static_members_table")));
	}
#else
	if (src->default_properties_table) {
		zval table;
		int i;
		array_init(&table);
		for (i = 0; i < src->default_properties_count; i++) {
			zval zv;
			ZVAL_COPY_VALUE(&zv, src->default_properties_table + i);
			add_next_index_zval(&table, &zv);
		}
		add_assoc_zval(dst, "default_properties_table", &table);
	} else {
		add_assoc_null_ex(dst, ("default_properties_table"), (sizeof("default_properties_table")));
	}

	if (src->default_static_members_table) {
		zval table;
		int i;
		array_init(&table);
		for (i = 0; i < src->default_static_members_count; i++) {
			zval zv;
			ZVAL_COPY_VALUE(&zv, src->default_static_members_table + i);
			add_next_index_zval(&table, &zv);
		}
		add_assoc_zval(dst, "default_static_members_table", &table);
	} else {
		add_assoc_null_ex(dst, ("default_static_members_table"), (sizeof("default_static_members_table")));
	}
#endif

	do {
		zval zv;
		array_init(&zv);
#ifdef PHP_WIN32
		__try { dasm_function_table(&zv, &src->function_table); }
		__except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		dasm_function_table(&zv, &src->function_table);
#endif
		add_assoc_zval(dst, "function_table", &zv);
	} while (0);

	do {
		zval zv;
		array_init(&zv);
#ifdef PHP_WIN32
		__try { dasm_properties_info(&zv, src, 0); } __except(EXCEPTION_EXECUTE_HANDLER) {}
		__try { dasm_properties_info(&zv, src, 1); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		dasm_properties_info(&zv, src, 0);
		dasm_properties_info(&zv, src, 1);
#endif
		add_assoc_zval(dst, "properties_info", &zv);
	} while (0);

	do {
		zval zv;
		array_init(&zv);
#ifdef PHP_WIN32
		__try { dasm_constants_table(&zv, src); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		dasm_constants_table(&zv, src);
#endif
		add_assoc_zval_ex(dst, ("constants_table"), (sizeof("constants_table")), &zv);
	} while (0);

	do {
		zval zv;
		array_init(&zv);
#ifdef PHP_WIN32
		__try { dasm_interfaces_list(&zv, src); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		dasm_interfaces_list(&zv, src);
#endif
		add_assoc_zval_ex(dst, ("interfaces"), (sizeof("interfaces")), &zv);
	} while (0);

	do {
		zval zv;
		array_init(&zv);
#ifdef PHP_WIN32
		__try { dasm_traits_list(&zv, src); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
		dasm_traits_list(&zv, src);
#endif
		add_assoc_zval_ex(dst, ("traits"), (sizeof("traits")), &zv);
	} while (0);
}

static void inline dasm_class_table(zval *dst, const HashTable *src)
{
	zend_class_entry *ce;
	ZEND_HASH_FOREACH_PTR((HashTable *)src, ce) {
		if (!ce) continue;
#ifdef PHP_WIN32
		if (!dasm_ic_committed_readable_ptr(ce)) continue;
#endif
		if (ce->type == ZEND_USER_CLASS) {
			const char *_ce_name = NULL;
			size_t _ce_name_len = 0;
#ifdef PHP_WIN32
			__try {
				if (ce->name && dasm_ic_committed_readable_ptr(ce->name)) {
					_ce_name = ZSTR_VAL(ce->name);
					_ce_name_len = ZSTR_LEN(ce->name);
				}
			} __except(EXCEPTION_EXECUTE_HANDLER) { _ce_name = NULL; }
#else
			if (ce->name) { _ce_name = ZSTR_VAL(ce->name); _ce_name_len = ZSTR_LEN(ce->name); }
#endif
			if (!_ce_name || _ce_name_len == 0 || _ce_name_len > 4096) continue;
			zval zv;
			array_init(&zv);
#ifdef PHP_WIN32
			__try {
				dasm_zend_class_entry(&zv, ce);
			} __except(EXCEPTION_EXECUTE_HANDLER) {
				add_assoc_string(&zv, "_dump_error", "SEH exception in dasm_zend_class_entry");
			}
#else
			dasm_zend_class_entry(&zv, ce);
#endif
			add_assoc_zval_ex(dst, _ce_name, _ce_name_len + 1, &zv);
		}
	} ZEND_HASH_FOREACH_END();
}

static void inline dasm_merge_extra_class_table(zval *dst)
{
	zend_string *key;
	zval *value;

	if (Z_TYPE(opcodedump_extra_class_table) != IS_ARRAY) return;
	ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL(opcodedump_extra_class_table), key, value) {
		zval copy;
		if (!key) continue;
		ZVAL_DUP(&copy, value);
		add_assoc_zval_ex(dst, ZSTR_VAL(key), ZSTR_LEN(key) + 1, &copy);
	} ZEND_HASH_FOREACH_END();
}

/* ============================================================
 * dasm_zend_op_array  (main dump function)
 * ============================================================ */
void dasm_zend_op_array(zval *dst, const zend_op_array *src)
{
	zend_op_array _ic_fixup;

	/* ionCube sentinel: opcodes field is a small odd integer before decode */
	if (src && src->opcodes && ((uintptr_t)(src->opcodes) & 3)) {
		const zend_op_array *_real = NULL;
		void *_ic_desc = NULL;
#ifdef PHP_WIN32
		__try {
			if (src->reserved[3]) {
				const uint32_t *_desc = (const uint32_t *)src->reserved[3];
				_ic_desc = src->reserved[3];
				uint32_t _fn_ptr_val = _desc[19];
				if (_fn_ptr_val) {
					const uint32_t *_fn_ptr = (const uint32_t *)_fn_ptr_val;
					uint32_t _real_oa_addr = _fn_ptr[10];
					if (_real_oa_addr) {
						const zend_op_array *_cand = (const zend_op_array *)_real_oa_addr;
						if (_cand->type == ZEND_USER_FUNCTION &&
						    _cand->last > 0 && _cand->last < 65536 &&
						    _cand->opcodes != NULL) {
							_real = _cand;
							ic_remember_desc(_cand, _ic_desc);
						}
					}
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_real = NULL;
		}
#endif
		if (_real) {
			_ic_fixup = *_real;
			_ic_fixup.reserved[3] = _ic_desc;
			src = &_ic_fixup;
		} else {
			memset(&_ic_fixup, 0, sizeof(_ic_fixup));
			_ic_fixup.type          = src->type;
			_ic_fixup.function_name = src->function_name;
			_ic_fixup.fn_flags      = src->fn_flags & ~ZEND_ACC_DONE_PASS_TWO;
			_ic_fixup.filename      = src->filename;
			src = &_ic_fixup;
		}
	}

#ifdef PHP_WIN32
	/* If force-decode could only restore descriptor state, dump the saved
	 * original opcode stream instead of the 28-byte ionCube sentinel. */
	if (src && src->reserved[3]) {
		__try {
			const uint32_t *_desc = (const uint32_t *)src->reserved[3];
			if (dasm_ic_committed_readable_ptr(_desc) &&
			    _desc[6] && (uintptr_t)src->opcodes == (uintptr_t)_desc[6]) {
				HMODULE _hLoader = GetModuleHandleA(IC_LOADER_NAME);
				uint32_t _decoded = _desc[15];
				if (_hLoader &&
				    dasm_ic_committed_readable_ptr((const void *)((uintptr_t)_hLoader + IC_REQUEST_KEY_RVA))) {
					uint32_t _request_key = *(const uint32_t *)((uintptr_t)_hLoader + IC_REQUEST_KEY_RVA);
					uint32_t _key_salt = *(const uint32_t *)((const char *)src + 0x5C); /* PHP 8.1: filename* bits */
					uint32_t _restore_key = _request_key + _key_salt + _desc[17];
					_decoded = _desc[5] ^ _restore_key;
				}
				if (_decoded) {
					_ic_fixup = *src;
					_ic_fixup.opcodes = (zend_op *)(uintptr_t)_decoded;
					if (_desc[27] > 0 && _desc[27] < 65536) _ic_fixup.last = _desc[27];
					_ic_fixup.line_end &= ~0x400000u; /* PHP 8.1: encode marker lives in line_end (+0x64) */
					src = &_ic_fixup;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
	}
#endif


	add_assoc_long_ex(dst, ("type"), (sizeof("type")), src->type);

	if (src->function_name == NULL) {
		add_assoc_null(dst, "function_name");
	} else {
		const char *_fn = NULL;
		size_t _fn_len = 0;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(src->function_name)) {
				_fn = ZSTR_VAL(src->function_name);
				_fn_len = ZSTR_LEN(src->function_name);
				if (_fn_len > 32768 ||
				    !dasm_ic_committed_readable_ptr(_fn) ||
				    !dasm_ic_committed_readable_ptr(_fn + _fn_len)) {
					_fn = NULL;
					_fn_len = 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_fn = NULL;
			_fn_len = 0;
		}
#else
		_fn = ZSTR_VAL(src->function_name);
		_fn_len = ZSTR_LEN(src->function_name);
#endif
		if (_fn) {
			add_assoc_stringl(dst, "function_name", (char *)_fn, _fn_len);
		} else {
			add_assoc_null(dst, "function_name");
		}
	}

	add_assoc_long_ex(dst, ("fn_flags"), (sizeof("fn_flags")), dasm_normalize_fn_flags(src->fn_flags));

	if (src->arg_info && src->num_args > 0 && src->num_args < 256
#ifdef PHP_WIN32
	    && dasm_ic_committed_readable_ptr(src->arg_info)
	    && dasm_ic_committed_readable_ptr(src->arg_info + src->num_args - 1)
#endif
	) {
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < (int)src->num_args; ++i) {
			zval zv;
			array_init(&zv);
#ifdef PHP_WIN32
			__try { dasm_zend_arg_info(&zv, &(src->arg_info[i])); }
			__except(EXCEPTION_EXECUTE_HANDLER) { add_assoc_null(&zv, "name"); }
#else
			dasm_zend_arg_info(&zv, &(src->arg_info[i]));
#endif
			add_next_index_zval(&arr, &zv);
		}
		add_assoc_zval(dst, "arg_info", &arr);
	} else {
		add_assoc_null(dst, "arg_info");
	}

	/* Return type hint: stored at arg_info[-1] when ZEND_ACC_HAS_RETURN_TYPE (0x40000000) is set.
	 * arg_info is allocated with an extra leading slot for the return info even when num_args == 0. */
	if ((src->fn_flags & ZEND_ACC_HAS_RETURN_TYPE) && src->arg_info != NULL
#ifdef PHP_WIN32
	    && dasm_ic_committed_readable_ptr(src->arg_info - 1)
#endif
	) {
		zval ret_zv;
		array_init(&ret_zv);
#ifdef PHP_WIN32
		__try { dasm_zend_arg_info(&ret_zv, src->arg_info - 1); }
		__except(EXCEPTION_EXECUTE_HANDLER) { add_assoc_null(&ret_zv, "name"); }
#else
		dasm_zend_arg_info(&ret_zv, src->arg_info - 1);
#endif
		add_assoc_zval(dst, "return_type_info", &ret_zv);
	} else {
		add_assoc_null(dst, "return_type_info");
	}

	add_assoc_long_ex(dst, ("num_args"),          (sizeof("num_args")),          src->num_args);
	add_assoc_long_ex(dst, ("required_num_args"), (sizeof("required_num_args")), src->required_num_args);

	if (src->refcount) {
		uint32_t _rc = 0;
#ifdef PHP_WIN32
		__try { _rc = src->refcount[0]; } __except(EXCEPTION_EXECUTE_HANDLER) { _rc = 0; }
#else
		_rc = src->refcount[0];
#endif
		add_assoc_long_ex(dst, ("refcount"), (sizeof("refcount")), _rc);
	} else {
		add_assoc_null_ex(dst, ("refcount"), (sizeof("refcount")));
	}

	/* Literals */
#ifdef PHP_WIN32
	if (src->literals && src->last_literal > 0 && src->last_literal < 65536) {
		SIZE_T _lit_size = (SIZE_T)(src->last_literal) * 16 + 64;
		DWORD _lit_old = 0;
		int _lit_unlocked = VirtualProtect((LPVOID)src->literals, _lit_size, PAGE_EXECUTE_READWRITE, &_lit_old);
		if (!_lit_unlocked)
			_lit_unlocked = VirtualProtect((LPVOID)src->literals, _lit_size, PAGE_READWRITE, &_lit_old);
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < src->last_literal; ++i) {
			zval zv;
			int _lm = 0;
			__try { ((volatile uint8_t *)src->literals)[i * 16 + 8]; _lm = 1; }
			__except(EXCEPTION_EXECUTE_HANDLER) { _lm = 0; }
			if (!_lm) break;
			array_init(&zv);
			__try { ZVAL_COPY_VALUE(&zv, &(src->literals[i])); }
			__except(EXCEPTION_EXECUTE_HANDLER) { ZVAL_NULL(&zv); }
			add_next_index_zval(&arr, &zv);
		}
		if (_lit_unlocked) VirtualProtect((LPVOID)src->literals, _lit_size, _lit_old, &_lit_old);
		add_assoc_zval_ex(dst, ("literals"), (sizeof("literals")), &arr);
	} else {
		add_assoc_null_ex(dst, ("literals"), (sizeof("literals")));
	}
#else
	if (src->literals && src->last_literal > 0 && src->last_literal < 65536) {
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < src->last_literal; ++i) {
			zval zv;
			array_init(&zv);
			ZVAL_COPY_VALUE(&zv, &(src->literals[i]));
			add_next_index_zval(&arr, &zv);
		}
		add_assoc_zval_ex(dst, ("literals"), (sizeof("literals")), &arr);
	} else {
		add_assoc_null_ex(dst, ("literals"), (sizeof("literals")));
	}
#endif

	add_assoc_long_ex(dst, ("last_literal"), (sizeof("last_literal")), src->last_literal);

	/* Opcodes */
#ifdef PHP_WIN32
	if (src->opcodes && src->last > 0 && src->last < 65536) {
		SIZE_T _op_size = (SIZE_T)(src->last) * sizeof(zend_op) + 128;
		DWORD _op_old = 0;
		int _op_unlocked = VirtualProtect((LPVOID)src->opcodes, _op_size, PAGE_EXECUTE_READWRITE, &_op_old);
		DWORD _lit2_old = 0;
		int _lit2_unlocked = 0;
		if (src->literals && src->last_literal > 0) {
			SIZE_T _lit2_size = (SIZE_T)(src->last_literal) * 16 + 64;
			_lit2_unlocked = VirtualProtect((LPVOID)src->literals, _lit2_size, PAGE_EXECUTE_READWRITE, &_lit2_old);
		}
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < (int)src->last; ++i) {
			zval zv;
			int _om = 0;
			__try { volatile zend_uchar _opcode_probe = src->opcodes[i].opcode; (void)_opcode_probe; _om = 1; }
			__except(EXCEPTION_EXECUTE_HANDLER) { _om = 0; }
			if (!_om) break;
			array_init(&zv);
			ic_decode_seh_index = (zend_long)i;
			ic_decode_seh_code = 0;
			ic_decode_seh_phase = 0;
			__try { dasm_zend_op(&zv, src, &(src->opcodes[i])); }
			__except((ic_decode_seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) { dasm_zend_op_minimal(&zv, src, &(src->opcodes[i])); }
			add_next_index_zval(&arr, &zv);
		}
		if (_op_unlocked)   VirtualProtect((LPVOID)src->opcodes,  _op_size,  _op_old,   &_op_old);
		if (_lit2_unlocked) VirtualProtect((LPVOID)src->literals, (SIZE_T)(src->last_literal)*16+64, _lit2_old, &_lit2_old);
		add_assoc_zval_ex(dst, ("opcodes"), (sizeof("opcodes")), &arr);
	} else {
		add_assoc_null_ex(dst, ("opcodes"), (sizeof("opcodes")));
	}
#else
	if (src->opcodes && src->last > 0 && src->last < 65536) {
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < (int)src->last; ++i) {
			zval zv;
			array_init(&zv);
			dasm_zend_op(&zv, src, &(src->opcodes[i]));
			add_next_index_zval(&arr, &zv);
		}
		add_assoc_zval_ex(dst, ("opcodes"), (sizeof("opcodes")), &arr);
	} else {
		add_assoc_null_ex(dst, ("opcodes"), (sizeof("opcodes")));
	}
#endif

	add_assoc_long_ex(dst, ("last"), (sizeof("last")), src->last);
	add_assoc_long_ex(dst, ("T"),    (sizeof("T")),    src->T);

#if defined(ZEND_ENGINE_MODERN)
	if (src->live_range && src->last_live_range > 0 && src->last_live_range < 65536
#ifdef PHP_WIN32
	    && dasm_ic_committed_readable_ptr(src->live_range)
	    && dasm_ic_committed_readable_ptr(src->live_range + src->last_live_range - 1)
#endif
	) {
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < src->last_live_range; ++i) {
			zval zv;
			array_init(&zv);
#ifdef PHP_WIN32
			__try { dasm_zend_live_range(&zv, &(src->live_range[i])); }
			__except(EXCEPTION_EXECUTE_HANDLER) { add_assoc_null(&zv, "var"); }
#else
			dasm_zend_live_range(&zv, &(src->live_range[i]));
#endif
			add_next_index_zval(&arr, &zv);
		}
		add_assoc_zval_ex(dst, ("live_range"),      (sizeof("live_range")),      &arr);
	} else {
		add_assoc_null_ex(dst, ("live_range"),      (sizeof("live_range")));
	}
	add_assoc_long_ex(dst, ("last_live_range"), (sizeof("last_live_range")), src->last_live_range);
#endif

	if (src->try_catch_array && src->last_try_catch > 0 && src->last_try_catch < 65536
#ifdef PHP_WIN32
	    && dasm_ic_committed_readable_ptr(src->try_catch_array)
	    && dasm_ic_committed_readable_ptr(src->try_catch_array + src->last_try_catch - 1)
#endif
	) {
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < src->last_try_catch; ++i) {
			zval zv;
			array_init(&zv);
#ifdef PHP_WIN32
			__try { dasm_zend_try_catch_element(&zv, &(src->try_catch_array[i])); }
			__except(EXCEPTION_EXECUTE_HANDLER) { add_assoc_null(&zv, "try_op"); }
#else
			dasm_zend_try_catch_element(&zv, &(src->try_catch_array[i]));
#endif
			add_next_index_zval(&arr, &zv);
		}
		add_assoc_zval_ex(dst, ("try_catch_array"), (sizeof("try_catch_array")), &arr);
	} else {
		add_assoc_null_ex(dst, ("try_catch_array"), (sizeof("try_catch_array")));
	}
	add_assoc_long_ex(dst, ("last_try_catch"), (sizeof("last_try_catch")), src->last_try_catch);

	if (src->static_variables) {
		zval zv;
		array_init(&zv);
#ifdef PHP_WIN32
		/* For step1-materialized ionCube op_arrays static_variables can be a
		 * stale/garbage pointer; guard the HashTable walk. */
		__try {
			if (dasm_ic_committed_readable_ptr(src->static_variables))
				dasm_HashTable(&zv, src->static_variables);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			zval_ptr_dtor(&zv);
			array_init(&zv);
		}
#else
		dasm_HashTable(&zv, src->static_variables);
#endif
		add_assoc_zval_ex(dst, ("static_variables"), (sizeof("static_variables")), &zv);
	} else {
		add_assoc_null_ex(dst, ("static_variables"), (sizeof("static_variables")));
	}

	if (src->filename == NULL) {
		add_assoc_null(dst, "filename");
	} else {
		const char *_fname = NULL;
		size_t _fname_len = 0;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(src->filename)) {
				_fname = ZSTR_VAL(src->filename);
				_fname_len = ZSTR_LEN(src->filename);
				if (_fname_len > 32768 ||
				    !dasm_ic_committed_readable_ptr(_fname) ||
				    !dasm_ic_committed_readable_ptr(_fname + _fname_len)) {
					_fname = NULL;
					_fname_len = 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_fname = NULL;
			_fname_len = 0;
		}
#else
		_fname = ZSTR_VAL(src->filename);
		_fname_len = ZSTR_LEN(src->filename);
#endif
		if (_fname) {
			add_assoc_stringl(dst, "filename", (char *)_fname, _fname_len);
		} else {
			add_assoc_string(dst, "filename", "(ionCube-protected)");
		}
	}

	if (src->doc_comment == NULL) {
		add_assoc_null(dst, "doc_comment");
		add_assoc_long(dst, "doc_comment_len", 0);
	} else {
		const char *_doc = NULL;
		size_t _doc_len = 0;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(src->doc_comment)) {
				_doc = ZSTR_VAL(src->doc_comment);
				_doc_len = ZSTR_LEN(src->doc_comment);
				if (_doc_len > 1048576 ||
				    !dasm_ic_committed_readable_ptr(_doc) ||
				    !dasm_ic_committed_readable_ptr(_doc + _doc_len)) {
					_doc = NULL;
					_doc_len = 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_doc = NULL;
			_doc_len = 0;
		}
#else
		_doc = ZSTR_VAL(src->doc_comment);
		_doc_len = ZSTR_LEN(src->doc_comment);
#endif
		if (_doc) {
			add_assoc_stringl(dst, "doc_comment", (char *)_doc, _doc_len);
			add_assoc_long(dst, "doc_comment_len", _doc_len);
		} else {
			add_assoc_null(dst, "doc_comment");
			add_assoc_long(dst, "doc_comment_len", 0);
		}
	}

	add_assoc_long_ex(dst, ("line_start"), (sizeof("line_start")), src->line_start & ~0x600000u);
	add_assoc_long_ex(dst, ("line_end"),   (sizeof("line_end")),   src->line_end   & ~0x600000u);
	/* early_binding field was removed from zend_op_array in PHP 8.0 */
	add_assoc_long_ex(dst, ("cache_size"), (sizeof("cache_size")), src->cache_size);

	/* Variables */
#ifdef PHP_WIN32
	{
		int _var_mem_ok = 0;
		if (src->vars && src->last_var > 0 && src->last_var < 65536) {
			__try { (void)src->vars[0]; _var_mem_ok = 1; } __except(EXCEPTION_EXECUTE_HANDLER) { _var_mem_ok = 0; }
		}
		if (_var_mem_ok) {
			int i;
			zval arr;
			array_init(&arr);
			for (i = 0; i < src->last_var; ++i) {
				zend_string *_vs = NULL;
				int _vm = 0;
				const char *_vname = NULL;
				size_t _vname_len = 0;
				__try {
					_vs = src->vars[i];
					if (_vs && dasm_ic_committed_readable_ptr(_vs)) {
						_vname = ZSTR_VAL(_vs);
						_vname_len = ZSTR_LEN(_vs);
						if (_vname_len > 32768 ||
						    !dasm_ic_committed_readable_ptr(_vname) ||
						    !dasm_ic_committed_readable_ptr(_vname + _vname_len)) {
							_vname = NULL;
							_vname_len = 0;
						}
					}
					_vm = 1;
				} __except(EXCEPTION_EXECUTE_HANDLER) { _vm = 0; }
				if (_vm && _vname) {
					add_next_index_stringl(&arr, _vname, _vname_len);
				} else {
					add_next_index_null(&arr);
				}
			}
			add_assoc_zval_ex(dst, ("vars"), (sizeof("vars")), &arr);
		} else {
			add_assoc_null_ex(dst, ("vars"), (sizeof("vars")));
		}
	}
#else
	if (src->vars && src->last_var > 0 && src->last_var < 65536) {
		int i;
		zval arr;
		array_init(&arr);
		for (i = 0; i < src->last_var; ++i) {
			add_next_index_string(&arr, ZSTR_VAL(src->vars[i]));
		}
		add_assoc_zval_ex(dst, ("vars"), (sizeof("vars")), &arr);
	} else {
		add_assoc_null_ex(dst, ("vars"), (sizeof("vars")));
	}
#endif

	add_assoc_long_ex(dst, ("last_var"), (sizeof("last_var")), src->last_var);

	if (src->prototype
#ifdef PHP_WIN32
	    && dasm_ic_committed_readable_ptr(src->prototype)
#endif
	) {
		zval zv;
		zend_op_array *op_array;
		array_init(&zv);
#ifdef PHP_WIN32
		__try {
			add_assoc_long(&zv, "type", src->prototype->type);
			op_array = &(src->prototype->op_array);
			dasm_zend_op_array(&zv, op_array);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			add_assoc_null(&zv, "type");
		}
#else
		add_assoc_long(&zv, "type", src->prototype->type);
		op_array = &(src->prototype->op_array);
		dasm_zend_op_array(&zv, op_array);
#endif
		add_assoc_zval_ex(dst, ("prototype"), (sizeof("prototype")), &zv);
	} else {
		add_assoc_null_ex(dst, ("prototype"), (sizeof("prototype")));
	}

	if (src->scope) {
		const char *_scope = NULL;
		size_t _scope_len = 0;
#ifdef PHP_WIN32
		__try {
			if (dasm_ic_committed_readable_ptr(src->scope) &&
			    dasm_ic_committed_readable_ptr(src->scope->name)) {
				_scope = ZSTR_VAL(src->scope->name);
				_scope_len = ZSTR_LEN(src->scope->name);
				if (_scope_len > 32768 ||
				    !dasm_ic_committed_readable_ptr(_scope) ||
				    !dasm_ic_committed_readable_ptr(_scope + _scope_len)) {
					_scope = NULL;
					_scope_len = 0;
				}
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			_scope = NULL;
			_scope_len = 0;
		}
#else
		_scope = ZSTR_VAL(src->scope->name);
		_scope_len = ZSTR_LEN(src->scope->name);
#endif
		if (_scope) {
			add_assoc_stringl(dst, "scope", (char *)_scope, _scope_len);
		} else {
			add_assoc_null_ex(dst, ("scope"), (sizeof("scope")));
		}
	} else {
		add_assoc_null_ex(dst, ("scope"), (sizeof("scope")));
	}

#ifdef PHP_WIN32
	__try { dasm_lambda_closures(dst, src); } __except(EXCEPTION_EXECUTE_HANDLER) {}
#else
	dasm_lambda_closures(dst, src);
#endif
}

/* ============================================================
 * ionCube force-decode  (Windows only)
 * ============================================================
 * PHP 8.1 loader (ioncube_loader_win_8.1.dll) — confirmed by binary analysis.
 * At encode time ionCube:
 *    - XOR-encodes op_array->opcodes into descriptor[5]
 *    - replaces opcodes with a small odd sentinel
 *    - saves `last` into descriptor[27], zeroes the field
 *    - ORs 0x400000 into the op_array line_end field (+0x64)
 *
 *  RVAs verified in IDA (ImageBase 0x10000000):
 *   IC_STEP1 = sub_10002C50 (reads [ecx+0x88]=reserved[3]=desc, desc[19]=fn_ptr,
 *                            calls the runtime decrypt callback; needs desc[19]!=0)
 *   IC_STEP2 = sub_10071660 (XOR-restore: opcodes = desc[5] ^ key, where
 *                            key = request_key + *(oa+0x5C) + desc[17];
 *                            restores `last` from desc[27]; clears 0x400000 at +0x64)
 *   IC_REQUEST_KEY = dword_101B01C8 (per-request XOR key dword)
 *
 *  Encode marker (same guard as step2):
 *    - op_array->reserved[3] != NULL  (descriptor present)
 *    - *(uint32_t*)((char*)oa + 0x64) & 0x400000  (bit in line_end)
 */
#ifdef PHP_WIN32
#ifndef IC_REQUEST_KEY_RVA
#define IC_REQUEST_KEY_RVA 0xB01C8u
#endif


static void opcodedump_capture_extra_function(const char *name, size_t name_len,
                                              zend_op_array *oa, uintptr_t loader_base)
{
	zval fn_zv, oa_zv;
	char key_buf[128];

	if (!oa) {
		return;
	}
	__try {
		if (oa->last < 0 || oa->last > 65536) {
			return;
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return;
	}
	if (Z_TYPE(opcodedump_extra_function_table) == IS_UNDEF) {
		array_init(&opcodedump_extra_function_table);
	}
	if (!name || name_len == 0 || name[0] == '\0') {
		snprintf(key_buf, sizeof(key_buf), "__ic_descriptor_function_%u",
		         opcodedump_descriptor_extra_functions);
		name = key_buf;
		name_len = strlen(key_buf);
	}
	array_init(&fn_zv);
	array_init(&oa_zv);
	__try {
		dasm_zend_op_array(&oa_zv, oa);
		add_assoc_zval(&fn_zv, "op_array", &oa_zv);
		add_assoc_zval_ex(&opcodedump_extra_function_table, name, name_len + 1, &fn_zv);
		opcodedump_descriptor_extra_functions++;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		zval_ptr_dtor(&oa_zv);
		zval_ptr_dtor(&fn_zv);
	}
}

static int opcodedump_descriptor_class_entry_looks_safe(zend_class_entry *ce)
{
	if (!ce || !dasm_ic_committed_readable_ptr(ce)) return 0;
	__try {
		if (ce->type != ZEND_USER_CLASS) return 0;
		if (!ce->name || !dasm_ic_committed_readable_ptr(ce->name)) return 0;
		if (ZSTR_LEN(ce->name) == 0 || ZSTR_LEN(ce->name) > 512) return 0;
		if (ce->function_table.nNumUsed > 2048) return 0;
		if (ce->function_table.nNumOfElements > ce->function_table.nNumUsed) return 0;
		if (ce->function_table.nTableSize > 4096) return 0;
		if (ce->function_table.nNumUsed > 0 &&
		    (!ce->function_table.arData ||
		     !dasm_ic_committed_readable_ptr(ce->function_table.arData))) {
			return 0;
		}
		if (ce->properties_info.nNumUsed > 2048) return 0;
		if (ce->properties_info.nNumUsed > 0 &&
		    (!ce->properties_info.arData ||
		     !dasm_ic_committed_readable_ptr(ce->properties_info.arData))) {
			return 0;
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
	return 1;
}

static void opcodedump_capture_extra_class(zend_class_entry *ce, uintptr_t loader_base)
{
	zval class_zv;
	(void)loader_base;

	if (!opcodedump_descriptor_class_entry_looks_safe(ce)) {
		return;
	}

	if (Z_TYPE(opcodedump_extra_class_table) == IS_UNDEF) {
		array_init(&opcodedump_extra_class_table);
	}
	array_init(&class_zv);
	__try {
		dasm_zend_class_entry(&class_zv, ce);
		add_assoc_zval_ex(&opcodedump_extra_class_table,
		                  ZSTR_VAL(ce->name), ZSTR_LEN(ce->name) + 1, &class_zv);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		zval_ptr_dtor(&class_zv);
	}
}

static void __fastcall opcodedump_process_module_descriptor(void *module_desc, uintptr_t loader_base)
{
	uint32_t *desc;
	uint32_t class_count, function_count, i;
	void **entries;

	if (!module_desc || !loader_base || opcodedump_descriptor_in_hook) return;
	opcodedump_descriptor_in_hook = 1;
	opcodedump_descriptor_last_module = module_desc;

	__try {
		desc = (uint32_t *)module_desc;
		if (!dasm_ic_committed_readable_ptr(desc) ||
		    !dasm_ic_committed_readable_ptr(desc + 8)) {
			goto done;
		}
		for (i = 0; i < 16; i++) {
			__try { opcodedump_descriptor_words[i] = desc[i]; }
			__except(EXCEPTION_EXECUTE_HANDLER) { opcodedump_descriptor_words[i] = 0; }
		}

		class_count = desc[0];
		function_count = desc[4];

		if (function_count > 0 && function_count <= 1024) {
			entries = (void **)(uintptr_t)desc[7];
			if (entries) {
				for (i = 0; i < function_count; i++) {
					void **entry = NULL;
					zend_op_array *oa = NULL;
					char *name = NULL;
					uint32_t name_len = 0;

					__try { entry = (void **)entries[i]; } __except(EXCEPTION_EXECUTE_HANDLER) { entry = NULL; }
					if (i < 8) opcodedump_descriptor_function_entries[i] = (uintptr_t)entry;
					if (!entry) {
						continue;
					}
					if (i == 0) {
						int wi;
						for (wi = 0; wi < 12; wi++) {
							__try { opcodedump_descriptor_first_function_entry_words[wi] = (uintptr_t)entry[wi]; }
							__except(EXCEPTION_EXECUTE_HANDLER) { opcodedump_descriptor_first_function_entry_words[wi] = 0; }
						}
						for (wi = 0; wi < 32; wi++) {
							__try { opcodedump_descriptor_first_function_oa_words[wi] = ((uintptr_t *)entry[0])[wi]; }
							__except(EXCEPTION_EXECUTE_HANDLER) { opcodedump_descriptor_first_function_oa_words[wi] = 0; }
						}
					}
					__try {
						oa = (zend_op_array *)entry[0];
						name = NULL;
						name_len = 0;
					} __except(EXCEPTION_EXECUTE_HANDLER) {
						continue;
					}
					if (!oa) continue;
					if (!opcodedump_descriptor_capture_enabled &&
					    opcodedump_descriptor_saved_function_count < OPCODEDUMP_DESCRIPTOR_SAVE_MAX) {
						opcodedump_descriptor_saved_functions[opcodedump_descriptor_saved_function_count++] = oa;
					}
					if (!name || !dasm_ic_committed_readable_ptr(name) || name[0] == '\0') {
						name = NULL;
						name_len = 0;
					}
					if (opcodedump_descriptor_capture_enabled ||
					    ic_env_flag_enabled("OPCODEDUMP_CAPTURE_DESCRIPTOR_DUMP")) {
						opcodedump_capture_extra_function(name, name_len, oa, loader_base);
					}
				}
			}
		}

		if (class_count > 0 && class_count <= 512) {
			entries = (void **)(uintptr_t)desc[3];
			if (entries) {
				for (i = 0; i < class_count; i++) {
					void **entry = NULL;
					zend_class_entry *ce = NULL;

					__try { entry = (void **)entries[i]; } __except(EXCEPTION_EXECUTE_HANDLER) { entry = NULL; }
					if (i < 8) opcodedump_descriptor_class_entries[i] = (uintptr_t)entry;
					if (!entry) {
						continue;
					}
					if (i == 0) {
						int wi;
						for (wi = 0; wi < 12; wi++) {
							__try { opcodedump_descriptor_first_class_entry_words[wi] = (uintptr_t)entry[wi]; }
							__except(EXCEPTION_EXECUTE_HANDLER) { opcodedump_descriptor_first_class_entry_words[wi] = 0; }
						}
					}
					__try { ce = (zend_class_entry *)entry[0]; } __except(EXCEPTION_EXECUTE_HANDLER) { ce = NULL; }
					if (ce && !opcodedump_descriptor_capture_enabled &&
					    opcodedump_descriptor_saved_class_count < OPCODEDUMP_DESCRIPTOR_SAVE_MAX) {
						opcodedump_descriptor_saved_classes[opcodedump_descriptor_saved_class_count++] = ce;
					}
					if (opcodedump_descriptor_capture_enabled ||
					    ic_env_flag_enabled("OPCODEDUMP_CAPTURE_DESCRIPTOR_DUMP")) {
						opcodedump_capture_extra_class(ce, loader_base);
					}
				}
			}
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {}

done:
	opcodedump_descriptor_in_hook = 0;
}

__declspec(naked) static void opcodedump_descriptor_preprocess_hook(void)
{
	__asm {
		pushfd
		pushad
		mov  edx, DWORD PTR [opcodedump_loader_base_cached]
		call opcodedump_process_module_descriptor
		popad
		popfd
		mov  eax, DWORD PTR [opcodedump_loader_base_cached]
		add  eax, 6C540h
		call eax
		mov  eax, DWORD PTR [opcodedump_loader_base_cached]
		add  eax, 6CE4Ah
		jmp  eax
	}
}

static int opcodedump_install_ic_descriptor_hook(void)
{
	HMODULE hLoader;
	unsigned char *target;
	DWORD old_protect, tmp_protect;
	intptr_t rel;

	if (opcodedump_descriptor_hook_installed) return 1;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;

	target = (unsigned char *)((uintptr_t)hLoader + IC_DESCRIPTOR_PREPROCESS_PATCH_RVA);

	if (!VirtualProtect(target, OPCODEDUMP_PATCH_LEN, PAGE_EXECUTE_READWRITE, &old_protect)) {
		return 0;
	}
	memcpy(opcodedump_descriptor_original, target, OPCODEDUMP_PATCH_LEN);
	target[0] = 0xE9;
	rel = (intptr_t)opcodedump_descriptor_preprocess_hook - (intptr_t)(target + 5);
	memcpy(target + 1, &rel, 4);
	FlushInstructionCache(GetCurrentProcess(), target, OPCODEDUMP_PATCH_LEN);
	VirtualProtect(target, OPCODEDUMP_PATCH_LEN, old_protect, &tmp_protect);

	opcodedump_loader_base_cached = (uintptr_t)hLoader;
	opcodedump_descriptor_target = target;
	opcodedump_descriptor_hook_installed = 1;
	return 1;
}

/* ============================================================
 * Materializer opcode capture
 * ============================================================
 * sub_1009B3C0 builds transient zend_op buffers and then sets each handler.
 * At RVA 0x9BD20, CH contains the real Zend opcode byte for the current
 * opline, and [esp+2c] is the current zend_op*. Capture that pair before the
 * loader branches to either sub_100701D0 or sub_10070170. */
#ifndef IC_OPCODE_CAPTURE_LOOP_RVA
#define IC_OPCODE_CAPTURE_LOOP_RVA 0x9BD20u
#endif
static unsigned char *opcodedump_opcode_capture_target = NULL;
static unsigned char opcodedump_opcode_capture_original[6];

__declspec(naked) static void opcodedump_opcode_capture_loop_hook(void)
{
	__asm {
		pushfd
		pushad
		movzx eax, ch
		push eax
		mov  eax, [esp+54h]       /* original [esp+2c] after pushfd/pushad/push */
		push eax
		call opcodedump_capture_materialized_opcode
		add  esp, 8
		popad
		popfd

		/* relocated original bytes:
		 *   cmp dword ptr [eax+10h], 6
		 *   jl  1009BD46
		 */
		cmp  DWORD PTR [eax+10h], 6
		jl   capture_loop_lt6
		mov  eax, DWORD PTR [opcodedump_loader_base_cached]
		add  eax, 9BD26h
		jmp  eax
	capture_loop_lt6:
		mov  eax, DWORD PTR [opcodedump_loader_base_cached]
		add  eax, 9BD46h
		jmp  eax
	}
}

static int opcodedump_install_opcode_capture_hook(void)
{
	HMODULE hLoader;
	unsigned char *target;
	DWORD old_protect, tmp_protect;
	intptr_t rel;
	static const unsigned char expect[6] = { 0x83, 0x78, 0x10, 0x06, 0x7C, 0x20 };

	if (opcodedump_opcode_capture_hook_installed) return 1;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;
	target = (unsigned char *)((uintptr_t)hLoader + IC_OPCODE_CAPTURE_LOOP_RVA);
	if (!VirtualProtect(target, sizeof(opcodedump_opcode_capture_original), PAGE_EXECUTE_READWRITE, &old_protect)) return 0;
	if (memcmp(target, expect, sizeof(expect)) != 0) {
		VirtualProtect(target, sizeof(opcodedump_opcode_capture_original), old_protect, &tmp_protect);
		return 0;
	}
	memcpy(opcodedump_opcode_capture_original, target, sizeof(opcodedump_opcode_capture_original));
	target[0] = 0xE9;
	rel = (intptr_t)opcodedump_opcode_capture_loop_hook - (intptr_t)(target + 5);
	memcpy(target + 1, &rel, 4);
	target[5] = 0x90;
	FlushInstructionCache(GetCurrentProcess(), target, sizeof(opcodedump_opcode_capture_original));
	VirtualProtect(target, sizeof(opcodedump_opcode_capture_original), old_protect, &tmp_protect);
	opcodedump_loader_base_cached = (uintptr_t)hLoader;
	opcodedump_opcode_capture_target = target;
	opcodedump_opcode_capture_hook_installed = 1;
	return 1;
}

/* Direct setter hook: sub_100701D0(ecx=zend_op*, dl=real_opcode). This catches
 * materialization paths that do not pass through the 0x9BD20 loop probe. */
#ifndef IC_OPCODE_SETTER_RVA
#define IC_OPCODE_SETTER_RVA 0x701D0u
#endif
static unsigned char *opcodedump_opcode_setter_target = NULL;
static unsigned char opcodedump_opcode_setter_original[5];

__declspec(naked) static void opcodedump_opcode_setter_hook(void)
{
	__asm {
		pushfd
		pushad
		movzx eax, dl
		push eax
		push ecx
		call opcodedump_capture_materialized_opcode
		add  esp, 8
		popad
		popfd

		/* relocated original bytes:
		 *   movzx eax, dl
		 *   push  esi
		 *   push  edi
		 */
		movzx eax, dl
		push esi
		push edi
		mov  edi, DWORD PTR [opcodedump_loader_base_cached]
		add  edi, 701D5h
		jmp  edi
	}
}

static int opcodedump_install_opcode_setter_hook(void)
{
	HMODULE hLoader;
	unsigned char *target;
	DWORD old_protect, tmp_protect;
	intptr_t rel;
	static const unsigned char expect[5] = { 0x0F, 0xB6, 0xC2, 0x56, 0x57 };

	if (opcodedump_opcode_setter_hook_installed) return 1;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;
	target = (unsigned char *)((uintptr_t)hLoader + IC_OPCODE_SETTER_RVA);
	if (!VirtualProtect(target, sizeof(opcodedump_opcode_setter_original), PAGE_EXECUTE_READWRITE, &old_protect)) return 0;
	if (memcmp(target, expect, sizeof(expect)) != 0) {
		VirtualProtect(target, sizeof(opcodedump_opcode_setter_original), old_protect, &tmp_protect);
		return 0;
	}
	memcpy(opcodedump_opcode_setter_original, target, sizeof(opcodedump_opcode_setter_original));
	target[0] = 0xE9;
	rel = (intptr_t)opcodedump_opcode_setter_hook - (intptr_t)(target + 5);
	memcpy(target + 1, &rel, 4);
	FlushInstructionCache(GetCurrentProcess(), target, sizeof(opcodedump_opcode_setter_original));
	VirtualProtect(target, sizeof(opcodedump_opcode_setter_original), old_protect, &tmp_protect);
	opcodedump_loader_base_cached = (uintptr_t)hLoader;
	opcodedump_opcode_setter_target = target;
	opcodedump_opcode_setter_hook_installed = 1;
	return 1;
}

/* ============================================================
 * Runtime opcode capture (ionCube VM dispatch detour)
 * ============================================================
 * The v15.5/8.1 loader executes encoded user functions through its OWN VM loop
 * (sub_1006FF10), bypassing zend_execute_ex entirely, and only materializes the
 * decrypted opcode stream during that dispatch. We detour the VM loop entry: at
 * that point op_array->opcodes (and desc[15]) hold the decrypted opcodes
 * (plaintext operands; handlers are still XOR-encrypted, which the dump does not
 * need). We snapshot there so the body never has to complete. */
#ifndef IC_VM_LOOP_RVA
#define IC_VM_LOOP_RVA 0x6FF10u
#endif
static unsigned char *opcodedump_vm_loop_target = NULL;
static unsigned char opcodedump_vm_loop_original[6];
static int opcodedump_vm_loop_hook_installed = 0;
/* Only active while we are deliberately driving functions to materialize them.
 * When active, the detour snapshots the (now decrypted) op_array at VM-loop entry
 * and then SKIPS the body entirely (returns to the loader without executing a
 * single opcode), so the encoded function never produces side effects. */
static volatile long opcodedump_materialize_active = 0;

static void ic_runtime_capture_execute_data(void *execute_data)
{
	__try {
		zend_op_array *oa;
		void *ic_desc;
		zend_op *real_ops;
		uint32_t real_last;
		ic_dynamic_saved_op_array *entry;

		if (!execute_data) return;
		oa = *(zend_op_array **)((char *)execute_data + 0x0C); /* execute_data->func */
		if (!oa || !dasm_ic_committed_readable_ptr(oa)) return;
		if (oa->type != ZEND_USER_FUNCTION) return;

		real_ops = oa->opcodes;
		real_last = oa->last;
		ic_desc = oa->reserved[3];
		if (ic_desc && dasm_ic_committed_readable_ptr(ic_desc)) {
			uint32_t d15 = ((const uint32_t *)ic_desc)[15];
			uint32_t d27 = ((const uint32_t *)ic_desc)[27];
			if (d15 && (d15 & 3) == 0 && dasm_ic_committed_readable_ptr((const void *)(uintptr_t)d15))
				real_ops = (zend_op *)(uintptr_t)d15;
			if (real_last == 0 && d27 > 0 && d27 < 65536) real_last = d27;
		}
		if (!real_ops || ((uintptr_t)real_ops & 3) != 0 || real_last == 0 || real_last >= 65536)
			return;

		/* Snapshot once per op_array (deep-copy stabilizes the transient buffer). */
		entry = ic_dynamic_register_saved(oa);
		if (entry && !entry->valid) {
			zend_op *prev_ops = oa->opcodes;
			uint32_t prev_last = oa->last;
			oa->opcodes = real_ops;
			oa->last = real_last;
			ic_dynamic_save_entry_copy(entry, oa);
			oa->opcodes = prev_ops;
			oa->last = prev_last;
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {}
}

__declspec(naked) static void opcodedump_vm_loop_hook(void)
{
	__asm {
		cmp  DWORD PTR [opcodedump_materialize_active], 0
		je   passthrough          /* normal execution: do nothing, run the body */
		pushfd
		pushad
		push ecx                  /* execute_data (ecx at VM-loop entry) */
		call ic_runtime_capture_execute_data
		add  esp, 4
		popad
		popfd
		/* Snapshot taken; skip the function body entirely. ecx had no stack args
		 * (__thiscall), so just return to the loader as if the frame completed. */
		mov  eax, -1
		ret
	passthrough:
		/* relocated original prologue: sub esp,8 ; push ebx ; mov ebx,ecx */
		sub  esp, 8
		push ebx
		mov  ebx, ecx
		mov  eax, DWORD PTR [opcodedump_loader_base_cached]
		add  eax, 6FF16h          /* sub_1006FF10 + 6 */
		jmp  eax
	}
}

static int opcodedump_install_vm_loop_hook(void)
{
	HMODULE hLoader;
	unsigned char *target;
	DWORD old_protect, tmp_protect;
	intptr_t rel;

	if (opcodedump_vm_loop_hook_installed) return 1;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;
	target = (unsigned char *)((uintptr_t)hLoader + IC_VM_LOOP_RVA);
	if (!VirtualProtect(target, 6, PAGE_EXECUTE_READWRITE, &old_protect)) return 0;
	memcpy(opcodedump_vm_loop_original, target, 6);
	target[0] = 0xE9;
	rel = (intptr_t)opcodedump_vm_loop_hook - (intptr_t)(target + 5);
	memcpy(target + 1, &rel, 4);
	target[5] = 0x90; /* nop */
	FlushInstructionCache(GetCurrentProcess(), target, 6);
	VirtualProtect(target, 6, old_protect, &tmp_protect);
	opcodedump_loader_base_cached = (uintptr_t)hLoader;
	opcodedump_vm_loop_target = target;
	opcodedump_vm_loop_hook_installed = 1;
	return 1;
}

/* The opcode materializer (sub_1009B3C0) sets each opline->handler to the real
 * php8.dll handler, then XOR-encrypts it with a per-opcode key:
 *     1009bd4e  call sub_100701D0      ; opline->handler = real handler
 *     ...
 *     1009bd6f  xor  [esi], ecx        ; *handler ^= key[index]*0x01010101
 * NOPping that 2-byte XOR leaves the real handler in the materialized buffer, so
 * the snapshot's handler->opcode map yields the true opcode directly. Execution
 * of those functions would then mismatch the dispatch-side XOR — harmless here
 * because the VM-loop detour skips the body during materialization. */
#ifndef IC_HANDLER_ENC_XOR_RVA
#define IC_HANDLER_ENC_XOR_RVA 0x9BD6Fu   /* sub_1009B3C0: xor [esi],ecx (branch 1) */
#endif
#ifndef IC_HANDLER_ENC_JZ_RVA
#define IC_HANDLER_ENC_JZ_RVA  0x70188u   /* sub_10070170: jz to real-handler path (branch 2) */
#endif
static int opcodedump_handler_enc_patched = 0;

static int opcodedump_patch_one(uintptr_t rva, const unsigned char *expect, const unsigned char *with, int len)
{
	HMODULE hLoader = GetModuleHandleA(IC_LOADER_NAME);
	unsigned char *target;
	DWORD old_protect, tmp;
	int ok = 0;
	if (!hLoader) return 0;
	target = (unsigned char *)((uintptr_t)hLoader + rva);
	if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old_protect)) return 0;
	if (memcmp(target, expect, len) == 0) {
		memcpy(target, with, len);
		ok = 1;
	} else if (memcmp(target, with, len) == 0) {
		ok = 1; /* already patched */
	}
	FlushInstructionCache(GetCurrentProcess(), target, len);
	VirtualProtect(target, len, old_protect, &tmp);
	return ok;
}

static int opcodedump_patch_disable_handler_encryption(void)
{
	/* Neutralize both opline->handler encryption sites in the materializer so the
	 * real php8.dll handler stays in the materialized opcode buffer:
	 *   branch 1 (sub_1009B3C0): NOP the `xor [esi],ecx`        (31 0E -> 90 90)
	 *   branch 2 (sub_10070170): force the real-handler path    (74 2F -> EB 2F) */
	static const unsigned char xor_from[2] = { 0x31, 0x0E }, xor_to[2] = { 0x90, 0x90 };
	static const unsigned char jz_from[2]  = { 0x74, 0x2F }, jz_to[2]  = { 0xEB, 0x2F };
	if (opcodedump_handler_enc_patched) return 1;
	opcodedump_patch_one(IC_HANDLER_ENC_XOR_RVA, xor_from, xor_to, 2);
	opcodedump_patch_one(IC_HANDLER_ENC_JZ_RVA,  jz_from,  jz_to,  2);
	opcodedump_handler_enc_patched = 1;
	return 1;
}

static int opcodedump_loader_bytes_match_mask(uintptr_t rva, const unsigned char *bytes,
                                              const char *mask, size_t len)
{
	HMODULE hLoader;
	unsigned char *target;
	size_t i;

	if (!bytes || !mask || len == 0) return 0;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;
	target = (unsigned char *)((uintptr_t)hLoader + rva);
	if (!dasm_ic_committed_readable_ptr(target) ||
	    !dasm_ic_committed_readable_ptr(target + len - 1)) return 0;

	for (i = 0; i < len; ++i) {
		if (mask[i] == 'x' && target[i] != bytes[i]) return 0;
	}
	return 1;
}

static int ic_op_array_looks_encoded_for_static_materialize(zend_op_array *oa)
{
	int encoded = 0;
	if (!oa || !dasm_ic_committed_readable_ptr(oa)) return 0;
	__try {
		if (oa->type != ZEND_USER_FUNCTION) return 0;
		if (!oa->reserved[3] || !dasm_ic_committed_readable_ptr(oa->reserved[3])) return 0;
		if (oa->opcodes && ((uintptr_t)oa->opcodes & 3u) != 0) encoded = 1;
		if ((oa->line_end & 0x600000u) != 0) encoded = 1;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		encoded = 0;
	}
	return encoded;
}

static int ic_static_materialize_op_array_snapshot(zend_op_array *oa)
{
	typedef int (__fastcall *ic_step1_fn)(zend_op_array *op_array);
	static const unsigned char step1_sig[] = {
		0x83, 0xEC, 0x14, 0xA1, 0x00, 0x00, 0x00, 0x00,
		0x53, 0x55, 0x56, 0x57, 0x8B, 0xF9, 0x89, 0x44,
		0x24, 0x1C, 0xB9, 0x06, 0x00, 0x00, 0x00, 0x8B,
		0x87, 0x88, 0x00, 0x00, 0x00
	};
	static const char step1_sig_mask[] = "xxxx????xxxxxxxxxxxxxxxxxxxxx";
	HMODULE hLoader;
	ic_step1_fn step1;
	zend_op_array original;
	ic_dynamic_saved_op_array *entry;
	int captured = 0;

	if (!ic_op_array_looks_encoded_for_static_materialize(oa)) return 0;
	hLoader = GetModuleHandleA(IC_LOADER_NAME);
	if (!hLoader) return 0;
	if (!opcodedump_loader_bytes_match_mask(IC_STEP1_RVA, step1_sig, step1_sig_mask,
	                                        sizeof(step1_sig))) return 0;
	step1 = (ic_step1_fn)((uintptr_t)hLoader + IC_STEP1_RVA);
	if (!step1 || !dasm_ic_committed_readable_ptr((const void *)step1)) return 0;

	entry = ic_dynamic_register_saved(oa);
	if (!entry) return 0;
	if (entry->valid) return 1;

	opcodedump_patch_disable_handler_encryption();
	__try { memcpy(&original, oa, sizeof(original)); }
	__except(EXCEPTION_EXECUTE_HANDLER) { return 0; }

	zend_try {
		__try { (void)step1(oa); }
		__except(EXCEPTION_EXECUTE_HANDLER) {}
	} zend_catch {} zend_end_try();

	__try {
		void *ic_desc = oa->reserved[3];
		zend_op *real_ops = oa->opcodes;
		uint32_t real_last = oa->last;

		if (ic_desc && dasm_ic_committed_readable_ptr(ic_desc)) {
			uint32_t d15 = ((const uint32_t *)ic_desc)[15];
			uint32_t d27 = ((const uint32_t *)ic_desc)[27];
			if (d15 && (d15 & 3u) == 0 &&
			    dasm_ic_committed_readable_ptr((const void *)(uintptr_t)d15)) {
				real_ops = (zend_op *)(uintptr_t)d15;
			}
			if (real_last == 0 && d27 > 0 && d27 < 65536) {
				real_last = d27;
			}
		}

		if (real_ops && ((uintptr_t)real_ops & 3u) == 0 &&
		    real_last > 0 && real_last < 65536) {
			oa->opcodes = real_ops;
			oa->last = real_last;
			ic_dynamic_save_entry_copy(entry, oa);
			captured = entry->valid ? 1 : 0;
		}
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		captured = 0;
	}

	__try { memcpy(oa, &original, sizeof(original)); }
	__except(EXCEPTION_EXECUTE_HANDLER) {}

	return captured;
}

static uint32_t ic_static_materialize_class_methods_from_table(HashTable *class_table)
{
	zend_class_entry *ce;
	uint32_t captured = 0;

	if (!class_table) return 0;
	ZEND_HASH_FOREACH_PTR(class_table, ce) {
		zend_function *zif;

		if (!ce || ce->type != ZEND_USER_CLASS) continue;
		ZEND_HASH_FOREACH_PTR(&ce->function_table, zif) {
			zend_op_array *oa;

			if (!zif || zif->type != ZEND_USER_FUNCTION) continue;
			oa = &zif->op_array;
			if (!oa->function_name) continue;
			__try {
				if (ic_static_materialize_op_array_snapshot(oa)) captured++;
			} __except(EXCEPTION_EXECUTE_HANDLER) {}
		} ZEND_HASH_FOREACH_END();
	} ZEND_HASH_FOREACH_END();

	return captured;
}

static uint32_t ic_static_materialize_all_class_methods(void)
{
	uint32_t captured = 0;

	if (CG(class_table)) {
		captured += ic_static_materialize_class_methods_from_table(CG(class_table));
	}
	if (EG(class_table) && EG(class_table) != CG(class_table)) {
		captured += ic_static_materialize_class_methods_from_table(EG(class_table));
	}
	return captured;
}

/* Drive every encoded user function through the loader VM so the dispatch detour
 * snapshots its decrypted opcodes. Calls use null stub args (>= num_args to avoid
 * ArgumentCountError, which is raised before the VM loop entry where we capture);
 * any TypeError/runtime error happens AFTER the snapshot and is swallowed. The
 * op_array pointers are collected first so calling user code cannot invalidate
 * the iterator. */
static uint32_t ic_runtime_materialize_all_functions(void)
{
	zend_op_array **list;
	uint32_t count = 0, cap = 0, i;
	zend_function *zif;

	if (!CG(function_table)) return 0;
	opcodedump_patch_disable_handler_encryption(); /* keep materialized handlers plaintext */
	cap = zend_hash_num_elements(CG(function_table));
	if (cap == 0) return 0;
	list = (zend_op_array **)ecalloc(cap, sizeof(zend_op_array *));
	if (!list) return 0;

	ZEND_HASH_FOREACH_PTR(CG(function_table), zif) {
		zend_op_array *oa;
		if (!zif || zif->type != ZEND_USER_FUNCTION) continue;
		oa = &zif->op_array;
		if (!oa->function_name || !oa->reserved[3]) continue; /* encoded only */
		if (count < cap) list[count++] = oa;
	} ZEND_HASH_FOREACH_END();

	opcodedump_materialize_active = 1; /* detour now snapshots + skips bodies */
	for (i = 0; i < count; ++i) {
		zend_op_array *oa = list[i];
		zval retval, params[16];
		zend_fcall_info fci;
		zend_fcall_info_cache fcc;
		uint32_t n, k;
		ic_dynamic_saved_op_array *e;

		__try { e = ic_dynamic_register_saved(oa); } __except(EXCEPTION_EXECUTE_HANDLER) { e = NULL; }
		if (e && e->valid) continue; /* already captured */

		n = oa->num_args;
		if (n > 16) n = 16;
		memset(&fci, 0, sizeof(fci));
		memset(&fcc, 0, sizeof(fcc));
		ZVAL_UNDEF(&retval);
		ZVAL_UNDEF(&fci.function_name);
		for (k = 0; k < n; ++k) ZVAL_NULL(&params[k]);

		fci.size = sizeof(fci);
		fci.retval = &retval;
		fci.params = params;
		fci.param_count = n;
		ZVAL_STR_COPY(&fci.function_name, oa->function_name);
		fcc.function_handler = (zend_function *)oa;
		fcc.calling_scope = oa->scope;
		fcc.called_scope = oa->scope;
		fcc.object = NULL;

		zend_try {
			__try { (void)zend_call_function(&fci, &fcc); }
			__except(EXCEPTION_EXECUTE_HANDLER) {}
		} zend_catch {} zend_end_try();

		if (Z_TYPE(retval) != IS_UNDEF) zval_ptr_dtor(&retval);
		if (Z_TYPE(fci.function_name) != IS_UNDEF) zval_ptr_dtor(&fci.function_name);
		if (EG(exception)) zend_clear_exception();
	}
	opcodedump_materialize_active = 0;

	efree(list);
	return count;
}
#endif /* PHP_WIN32 */

static const char *opcodedump_basename(const char *path)
{
	const char *base = path;
	const char *p;
	if (!path) return "";
	for (p = path; *p; ++p) {
		if (*p == '/' || *p == '\\') base = p + 1;
	}
	return base;
}

static int opcodedump_path_matches_capture_target(const char *candidate)
{
#ifdef PHP_WIN32
	char target[4096];
	DWORD n;
	const char *candidate_base;
	const char *target_base;

	if (candidate == NULL || candidate[0] == '\0') return 0;
	n = GetEnvironmentVariableA("OPCODEDUMP_CAPTURE_FILE", target, sizeof(target));
	if (n == 0 || n >= sizeof(target) || target[0] == '\0') return 0;

	if (_stricmp(candidate, target) == 0) return 1;
	candidate_base = opcodedump_basename(candidate);
	target_base = opcodedump_basename(target);
	return candidate_base[0] != '\0' && target_base[0] != '\0' &&
	       _stricmp(candidate_base, target_base) == 0;
#else
	(void)candidate;
	return 0;
#endif
}

#define OPCODEDUMP_IONCUBE_CALL_LOG_MAX 65536u

static void opcodedump_reset_ioncube_call_log(void)
{
	if (Z_TYPE(opcodedump_ioncube_call_log) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_ioncube_call_log);
	}
	array_init(&opcodedump_ioncube_call_log);
	opcodedump_ioncube_call_seen = 0;
	opcodedump_ioncube_call_captured = 0;
	opcodedump_ioncube_call_truncated = 0;
	opcodedump_ioncube_call_sequence = 0;
}

static int opcodedump_is_ioncube_function_name(zend_string *name)
{
	static const char prefix[] = "ioncube_";
	size_t i;
	const char *s;

	if (!name || ZSTR_LEN(name) < (sizeof(prefix) - 1)) {
		return 0;
	}
	s = ZSTR_VAL(name);
	for (i = 0; i < sizeof(prefix) - 1; ++i) {
		char c = s[i];
		if (c >= 'A' && c <= 'Z') {
			c = (char)(c - 'A' + 'a');
		}
		if (c != prefix[i]) {
			return 0;
		}
	}
	return 1;
}

static const char *opcodedump_zval_type_name(zval *value)
{
	if (!value) return "missing";
	switch (Z_TYPE_P(value)) {
		case IS_UNDEF: return "undef";
		case IS_NULL: return "null";
		case IS_FALSE: return "false";
		case IS_TRUE: return "true";
		case IS_LONG: return "int";
		case IS_DOUBLE: return "float";
		case IS_STRING: return "string";
		case IS_ARRAY: return "array";
		case IS_OBJECT: return "object";
		case IS_RESOURCE: return "resource";
		case IS_REFERENCE: return "reference";
		case IS_CONSTANT_AST: return "constant_ast";
		case IS_INDIRECT: return "indirect";
		default: return "unknown";
	}
}

static void opcodedump_add_assoc_long_exact(zval *dst, const char *key, zend_long value)
{
	add_assoc_long_ex(dst, key, strlen(key) + 1, value);
}

static void opcodedump_add_assoc_bool_exact(zval *dst, const char *key, zend_bool value)
{
	add_assoc_bool_ex(dst, key, strlen(key) + 1, value);
}

static void opcodedump_add_assoc_null_exact(zval *dst, const char *key)
{
	add_assoc_null_ex(dst, key, strlen(key) + 1);
}

static void opcodedump_add_assoc_zval_exact(zval *dst, const char *key, zval *value)
{
	add_assoc_zval_ex(dst, key, strlen(key) + 1, value);
}

static zval *opcodedump_deref_zval(zval *value)
{
	if (!value) return NULL;
	ZVAL_DEINDIRECT(value);
	ZVAL_DEREF(value);
	return value;
}

static void opcodedump_add_zval_copy_assoc(zval *dst, const char *key, zval *src)
{
	zval copy;
	zval *value = opcodedump_deref_zval(src);

	if (!value || Z_TYPE_P(value) == IS_UNDEF) {
		opcodedump_add_assoc_null_exact(dst, key);
		return;
	}
	ZVAL_DUP(&copy, value);
	opcodedump_add_assoc_zval_exact(dst, key, &copy);
}

static void opcodedump_add_zval_copy_index(zval *dst, zend_ulong index, zval *src)
{
	zval copy;
	zval *value = opcodedump_deref_zval(src);

	if (!value || Z_TYPE_P(value) == IS_UNDEF) {
		add_index_null(dst, index);
		return;
	}
	ZVAL_DUP(&copy, value);
	add_index_zval(dst, index, &copy);
}

static void opcodedump_add_caller_info(zval *entry, zend_execute_data *caller)
{
	zend_function *caller_func = caller ? caller->func : NULL;

	if (!caller_func) {
		opcodedump_add_assoc_null_exact(entry, "caller_type");
		opcodedump_add_assoc_null_exact(entry, "caller_function_name");
		opcodedump_add_assoc_null_exact(entry, "caller_filename");
		opcodedump_add_assoc_null_exact(entry, "caller_line");
		opcodedump_add_assoc_null_exact(entry, "caller_opcode_index");
		return;
	}

	opcodedump_add_assoc_long_exact(entry, "caller_type", (zend_long)caller_func->type);

	if (caller_func->type == ZEND_USER_FUNCTION) {
		zend_op_array *oa = &caller_func->op_array;
		const zend_op *opline = caller ? caller->opline : NULL;

		dasm_add_zend_string_and_hex(entry, "caller_function_name",
		                             "caller_function_name_hex", oa->function_name);
		dasm_add_zend_string_and_hex(entry, "caller_filename",
		                             "caller_filename_hex", oa->filename);
		if (oa->scope) {
			dasm_add_zend_string_and_hex(entry, "caller_scope",
			                             "caller_scope_hex", oa->scope->name);
		} else {
			opcodedump_add_assoc_null_exact(entry, "caller_scope");
			opcodedump_add_assoc_null_exact(entry, "caller_scope_hex");
		}

		if (opline) {
			opcodedump_add_assoc_long_exact(entry, "caller_line", (zend_long)opline->lineno);
			opcodedump_add_assoc_long_exact(entry, "caller_opcode", (zend_long)opline->opcode);
			if (zend_get_opcode_name(opline->opcode)) {
				add_assoc_string(entry, "caller_opcode_name", (char *)zend_get_opcode_name(opline->opcode));
			} else {
				opcodedump_add_assoc_null_exact(entry, "caller_opcode_name");
			}
			if (oa->opcodes && oa->last > 0 &&
			    opline >= oa->opcodes && opline < oa->opcodes + oa->last) {
				opcodedump_add_assoc_long_exact(entry, "caller_opcode_index", (zend_long)(opline - oa->opcodes));
			} else {
				opcodedump_add_assoc_null_exact(entry, "caller_opcode_index");
			}
		} else {
			opcodedump_add_assoc_null_exact(entry, "caller_line");
			opcodedump_add_assoc_null_exact(entry, "caller_opcode");
			opcodedump_add_assoc_null_exact(entry, "caller_opcode_name");
			opcodedump_add_assoc_null_exact(entry, "caller_opcode_index");
		}

		if (oa->filename) {
			opcodedump_add_assoc_bool_exact(entry, "caller_matches_capture_target",
			                                opcodedump_path_matches_capture_target(ZSTR_VAL(oa->filename)));
		} else {
			opcodedump_add_assoc_bool_exact(entry, "caller_matches_capture_target", 0);
		}
	} else {
		dasm_add_zend_string_and_hex(entry, "caller_function_name",
		                             "caller_function_name_hex", caller_func->common.function_name);
		opcodedump_add_assoc_null_exact(entry, "caller_filename");
		opcodedump_add_assoc_null_exact(entry, "caller_filename_hex");
		opcodedump_add_assoc_null_exact(entry, "caller_scope");
		opcodedump_add_assoc_null_exact(entry, "caller_scope_hex");
		opcodedump_add_assoc_null_exact(entry, "caller_line");
		opcodedump_add_assoc_null_exact(entry, "caller_opcode");
		opcodedump_add_assoc_null_exact(entry, "caller_opcode_name");
		opcodedump_add_assoc_null_exact(entry, "caller_opcode_index");
		opcodedump_add_assoc_bool_exact(entry, "caller_matches_capture_target", 0);
	}
}

static void opcodedump_capture_ioncube_call(zend_execute_data *execute_data, zval *return_value)
{
	zend_function *func = execute_data ? execute_data->func : NULL;
	zval entry, args;
	uint32_t argc, i;
	zval *ret = opcodedump_deref_zval(return_value);
	int capture_all = ic_env_flag_enabled("OPCODEDUMP_CAPTURE_ALL_INTERNAL");

	if (!func || (!capture_all && !opcodedump_is_ioncube_function_name(func->common.function_name))) {
		return;
	}

	opcodedump_ioncube_call_seen++;
	if (Z_TYPE(opcodedump_ioncube_call_log) == IS_UNDEF) {
		array_init(&opcodedump_ioncube_call_log);
	}
	if (opcodedump_ioncube_call_captured >= OPCODEDUMP_IONCUBE_CALL_LOG_MAX) {
		opcodedump_ioncube_call_truncated++;
		return;
	}

	array_init(&entry);
	opcodedump_add_assoc_long_exact(&entry, "seq", (zend_long)++opcodedump_ioncube_call_sequence);
	dasm_add_zend_string_and_hex(&entry, "function_name",
	                             "function_name_hex", func->common.function_name);
	if (func->type == ZEND_INTERNAL_FUNCTION && func->internal_function.module) {
		if (func->internal_function.module->name) {
			add_assoc_string(&entry, "module_name", (char *)func->internal_function.module->name);
		} else {
			opcodedump_add_assoc_null_exact(&entry, "module_name");
		}
	} else {
		opcodedump_add_assoc_null_exact(&entry, "module_name");
	}
	opcodedump_add_assoc_bool_exact(&entry, "capture_all_internal", capture_all ? 1 : 0);
	if (func->common.scope) {
		dasm_add_zend_string_and_hex(&entry, "scope",
		                             "scope_hex", func->common.scope->name);
	} else {
		opcodedump_add_assoc_null_exact(&entry, "scope");
		opcodedump_add_assoc_null_exact(&entry, "scope_hex");
	}

	argc = execute_data ? ZEND_CALL_NUM_ARGS(execute_data) : 0;
	opcodedump_add_assoc_long_exact(&entry, "argc", (zend_long)argc);
	array_init(&args);
	for (i = 0; i < argc; ++i) {
		opcodedump_add_zval_copy_index(&args, (zend_ulong)i, ZEND_CALL_ARG(execute_data, i + 1));
	}
	opcodedump_add_assoc_zval_exact(&entry, "args", &args);

	if (ret && Z_TYPE_P(ret) != IS_UNDEF) {
		opcodedump_add_assoc_long_exact(&entry, "return_type", (zend_long)Z_TYPE_P(ret));
		add_assoc_string(&entry, "return_type_name", (char *)opcodedump_zval_type_name(ret));
		opcodedump_add_zval_copy_assoc(&entry, "return_value", ret);
	} else {
		opcodedump_add_assoc_long_exact(&entry, "return_type", (zend_long)IS_UNDEF);
		add_assoc_string(&entry, "return_type_name", "undef");
		opcodedump_add_assoc_null_exact(&entry, "return_value");
	}
	opcodedump_add_assoc_bool_exact(&entry, "exception", EG(exception) ? 1 : 0);
	opcodedump_add_caller_info(&entry, execute_data ? execute_data->prev_execute_data : NULL);

	add_next_index_zval(&opcodedump_ioncube_call_log, &entry);
	opcodedump_ioncube_call_captured++;
}

static void opcodedump_add_ioncube_call_log(zval *dst)
{
	zval calls;

	if (Z_TYPE(opcodedump_ioncube_call_log) == IS_ARRAY) {
		ZVAL_DUP(&calls, &opcodedump_ioncube_call_log);
	} else {
		array_init(&calls);
	}

	opcodedump_add_assoc_long_exact(dst, "ioncube_api_seen", (zend_long)opcodedump_ioncube_call_seen);
	opcodedump_add_assoc_long_exact(dst, "ioncube_api_captured", (zend_long)opcodedump_ioncube_call_captured);
	opcodedump_add_assoc_long_exact(dst, "ioncube_api_truncated", (zend_long)opcodedump_ioncube_call_truncated);
	opcodedump_add_assoc_zval_exact(dst, "ioncube_api_calls", &calls);
}



static zend_op_array *opcodedump_compile_file_hook(zend_file_handle *file_handle, int type)
{
	if (opcodedump_orig_compile_file) {
		return opcodedump_orig_compile_file(file_handle, type);
	}
	return compile_file(file_handle, type);
}

static void opcodedump_execute_ex_hook(zend_execute_data *execute_data)
{
	if (opcodedump_orig_execute_ex) {
		opcodedump_orig_execute_ex(execute_data);
	} else {
		execute_ex(execute_data);
	}
}

static void opcodedump_execute_internal_hook(zend_execute_data *execute_data, zval *return_value)
{
	if (opcodedump_orig_execute_internal) {
		opcodedump_orig_execute_internal(execute_data, return_value);
	} else {
		execute_internal(execute_data, return_value);
	}

#ifdef PHP_WIN32
	__try {
		opcodedump_capture_ioncube_call(execute_data, return_value);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	}
#else
	opcodedump_capture_ioncube_call(execute_data, return_value);
#endif
}

/* ============================================================
 * PHP functions
 * ============================================================ */
#ifdef ZEND_BEGIN_ARG_INFO_EX
ZEND_BEGIN_ARG_INFO_EX(arginfo_dasm_file, 0, 0, 1)
	ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()
#else
static unsigned char arginfo_dasm_file[] = { 1, BYREF_NONE };
#endif

PHP_FUNCTION(dasm_file)
{
	char *filename;
	size_t filename_len;
	int compile_bailout = 0;
	int force_decode_bailout = 0;
#ifdef PHP_WIN32
	DWORD compile_seh = 0;
#endif

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &filename, &filename_len) == FAILURE) {
		return;
	}
	if (!filename_len) RETVAL_FALSE;

	opcodedump_reset_ioncube_call_log();

	zend_op_array *op_array = NULL;
	zval zfilename;
#ifdef PHP_WIN32
	uintptr_t loader_base = 0;
	{
		HMODULE hLoader = GetModuleHandleA(IC_LOADER_NAME);
		if (hLoader) {
			loader_base = (uintptr_t)hLoader;
		}
	}
#endif
	ZVAL_STRING(&zfilename, filename);
	zend_try {
#ifdef PHP_WIN32
		__try {
			op_array = compile_filename(ZEND_REQUIRE, Z_STR(zfilename)); /* PHP 8.0+: zend_string* arg */
		} __except(EXCEPTION_EXECUTE_HANDLER) {
			compile_seh = GetExceptionCode();
			op_array = NULL;
		}
#else
		op_array = compile_filename(ZEND_REQUIRE, Z_STR(zfilename)); /* PHP 8.0+: zend_string* arg */
#endif
	} zend_catch {
		compile_bailout = 1;
		op_array = NULL;
	} zend_end_try();

#ifdef PHP_WIN32
	{
		if (loader_base) {
			/* Runtime materialization: drive every encoded function through the
			 * loader VM so the dispatch detour snapshots its decrypted opcodes.
			 * This is the reliable path for v15.5/8.1 (standalone step1 only yields
			 * an encrypted intermediate). It must run INSTEAD of ic_force_decode,
			 * which would otherwise overwrite op_array->opcodes and make the
			 * functions uncallable. */
			if (op_array &&
			    (ic_env_flag_enabled("OPCODEDUMP_RUNTIME_MATERIALIZE") ||
			     ic_env_flag_enabled("OPCODEDUMP_MATERIALIZE_MAIN")) &&
			    !ic_env_flag_enabled("OPCODEDUMP_DISABLE_MAIN_MATERIALIZE")) {
				zend_try {
					__try { ic_static_materialize_op_array_snapshot(op_array); }
					__except(EXCEPTION_EXECUTE_HANDLER) {}
				} zend_catch { force_decode_bailout = 1; } zend_end_try();
			}
			if (ic_env_flag_enabled("OPCODEDUMP_RUNTIME_MATERIALIZE")) {
				/* Class methods are not present in CG(function_table), and
				 * non-static methods cannot be safely driven without an object.
				 * Snapshot their encoded bodies directly; step1 restores the
				 * original method op_array after copying the materialized body. */
				zend_try {
					__try { ic_static_materialize_all_class_methods(); }
					__except(EXCEPTION_EXECUTE_HANDLER) {}
				} zend_catch { force_decode_bailout = 1; } zend_end_try();

				/* Drive every encoded function through the loader VM so the dispatch
				 * detour snapshots its decrypted opcodes. The top-level {main} is
				 * handled above by a direct static materializer snapshot because it
				 * is not callable through zend_call_function. */
				zend_try {
					__try { ic_runtime_materialize_all_functions(); }
					__except(EXCEPTION_EXECUTE_HANDLER) {}
				} zend_catch { force_decode_bailout = 1; } zend_end_try();
			}
		}
	}
#endif

	if (op_array) {
		op_array->line_start &= ~0x600000u; /* 0x600000 covers the 0x400000 ionCube marker too */
		op_array->line_end   &= ~0x600000u;
	}

	array_init(return_value);

	zval zv;
	array_init(&zv);
	if (op_array) {
		zend_op_array *dump_op_array = op_array;
#ifdef PHP_WIN32
		__try {
			ic_dynamic_saved_op_array *main_saved =
			    ic_dynamic_find_saved_for_dump(op_array, NULL);
			if (main_saved && main_saved->valid) {
				dump_op_array = &main_saved->copy;
			}
		} __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif
		dasm_zend_op_array(&zv, dump_op_array);
	}
	add_assoc_string(return_value, "filename", filename);
	if (compile_bailout) {
		add_assoc_bool(return_value, "compile_bailout", 1);
	}
	if (force_decode_bailout) {
		add_assoc_bool(return_value, "force_decode_bailout", 1);
	}
#ifdef PHP_WIN32
	if (compile_seh) {
		add_assoc_long(return_value, "compile_seh", (zend_long)compile_seh);
	}
#endif
	add_assoc_zval_ex(return_value, ZEND_STRS("op_array"), &zv);

	if (CG(function_table) || EG(function_table)) {
		zval _zv;
		array_init(&_zv);
		if (CG(function_table)) {
			dasm_function_table(&_zv, CG(function_table));
		}
		if (EG(function_table) && EG(function_table) != CG(function_table)) {
			dasm_function_table(&_zv, EG(function_table));
		}
		dasm_merge_extra_function_table(&_zv);
		add_assoc_zval_ex(return_value, ("function_table"), (sizeof("function_table")), &_zv);
	} else {
		zval _zv;
		array_init(&_zv);
		dasm_merge_extra_function_table(&_zv);
		add_assoc_zval_ex(return_value, ("function_table"), (sizeof("function_table")), &_zv);
	}

	if (CG(class_table) || EG(class_table)) {
		zval _zv;
		array_init(&_zv);
		if (CG(class_table)) {
			dasm_class_table(&_zv, CG(class_table));
		}
		if (EG(class_table) && EG(class_table) != CG(class_table)) {
			dasm_class_table(&_zv, EG(class_table));
		}
		dasm_merge_extra_class_table(&_zv);
		add_assoc_zval_ex(return_value, ("class_table"), (sizeof("class_table")), &_zv);
	} else {
		zval _zv;
		array_init(&_zv);
		dasm_merge_extra_class_table(&_zv);
		add_assoc_zval_ex(return_value, ("class_table"), (sizeof("class_table")), &_zv);
	}

	opcodedump_add_ioncube_call_log(return_value);

	zval_ptr_dtor(&zfilename);
}

PHP_MINIT_FUNCTION(opcodedump)
{
	ZVAL_UNDEF(&opcodedump_extra_function_table);
	ZVAL_UNDEF(&opcodedump_extra_class_table);
	ZVAL_UNDEF(&opcodedump_ioncube_call_log);
	opcodedump_install_hooks();
#ifdef PHP_WIN32
	opcodedump_install_ic_descriptor_hook();
	if (!ic_env_flag_enabled("OPCODEDUMP_DISABLE_OPCODE_CAPTURE_HOOK"))
		opcodedump_install_opcode_capture_hook();
	if (!ic_env_flag_enabled("OPCODEDUMP_DISABLE_OPCODE_SETTER_HOOK"))
		opcodedump_install_opcode_setter_hook();
	/* Runtime opcode capture: detour the ionCube VM dispatch loop so encoded
	 * functions are snapshotted (decrypted) when they are dispatched. */
	if (!ic_env_flag_enabled("OPCODEDUMP_DISABLE_VM_LOOP_HOOK"))
		opcodedump_install_vm_loop_hook();
#endif
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(opcodedump)
{
	if (zend_compile_file == opcodedump_compile_file_hook) {
		zend_compile_file = opcodedump_orig_compile_file;
	}
	if (zend_execute_ex == opcodedump_execute_ex_hook) {
		zend_execute_ex = opcodedump_orig_execute_ex;
	}
	if (zend_execute_internal == opcodedump_execute_internal_hook) {
		zend_execute_internal = opcodedump_orig_execute_internal;
	}
	if (Z_TYPE(opcodedump_extra_function_table) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_extra_function_table);
	}
	ZVAL_UNDEF(&opcodedump_extra_function_table);
	if (Z_TYPE(opcodedump_extra_class_table) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_extra_class_table);
	}
	ZVAL_UNDEF(&opcodedump_extra_class_table);
	if (Z_TYPE(opcodedump_ioncube_call_log) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_ioncube_call_log);
	}
	ZVAL_UNDEF(&opcodedump_ioncube_call_log);
	opcodedump_orig_compile_file = NULL;
	opcodedump_orig_execute_ex = NULL;
	opcodedump_orig_execute_internal = NULL;
	return SUCCESS;
}

PHP_RINIT_FUNCTION(opcodedump)
{
#if defined(COMPILE_DL_OPCODEDUMP) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
#ifdef PHP_WIN32
	opcodedump_opcode_capture_reset_map();
#endif
	if (Z_TYPE(opcodedump_extra_function_table) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_extra_function_table);
	}
	ZVAL_UNDEF(&opcodedump_extra_function_table);
	if (Z_TYPE(opcodedump_extra_class_table) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_extra_class_table);
	}
	ZVAL_UNDEF(&opcodedump_extra_class_table);
	opcodedump_reset_ioncube_call_log();
	opcodedump_execute_hook_last_filename[0] = '\0';
	opcodedump_execute_hook_last_function[0] = '\0';
	opcodedump_compile_hook_last_before[0] = '\0';
	opcodedump_compile_hook_last_after[0] = '\0';
	opcodedump_compile_hook_last_oa[0] = '\0';
	memset(opcodedump_descriptor_words, 0, sizeof(opcodedump_descriptor_words));
	memset(opcodedump_descriptor_class_entries, 0, sizeof(opcodedump_descriptor_class_entries));
	memset(opcodedump_descriptor_function_entries, 0, sizeof(opcodedump_descriptor_function_entries));
	memset(opcodedump_descriptor_first_function_entry_words, 0, sizeof(opcodedump_descriptor_first_function_entry_words));
	memset(opcodedump_descriptor_first_class_entry_words, 0, sizeof(opcodedump_descriptor_first_class_entry_words));
	memset(opcodedump_descriptor_first_function_oa_words, 0, sizeof(opcodedump_descriptor_first_function_oa_words));
	opcodedump_descriptor_last_module = NULL;
	opcodedump_descriptor_capture_enabled = 0;
	opcodedump_descriptor_saved_function_count = 0;
	memset(opcodedump_descriptor_saved_functions, 0, sizeof(opcodedump_descriptor_saved_functions));
	opcodedump_descriptor_saved_class_count = 0;
	memset(opcodedump_descriptor_saved_classes, 0, sizeof(opcodedump_descriptor_saved_classes));
	opcodedump_descriptor_extra_functions = 0;
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(opcodedump)
{
	if (Z_TYPE(opcodedump_extra_function_table) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_extra_function_table);
		ZVAL_UNDEF(&opcodedump_extra_function_table);
	}
	if (Z_TYPE(opcodedump_extra_class_table) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_extra_class_table);
		ZVAL_UNDEF(&opcodedump_extra_class_table);
	}
	if (Z_TYPE(opcodedump_ioncube_call_log) != IS_UNDEF) {
		zval_ptr_dtor(&opcodedump_ioncube_call_log);
		ZVAL_UNDEF(&opcodedump_ioncube_call_log);
	}
	return SUCCESS;
}

PHP_MINFO_FUNCTION(opcodedump)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "opcodedump support", "enabled");
	php_info_print_table_end();
}

const zend_function_entry opcodedump_functions[] = {
	PHP_FE(dasm_file,   arginfo_dasm_file)
	PHP_FE_END
};

zend_module_entry opcodedump_module_entry = {
	STANDARD_MODULE_HEADER,
	"opcodedump",
	opcodedump_functions,
	PHP_MINIT(opcodedump),
	PHP_MSHUTDOWN(opcodedump),
	PHP_RINIT(opcodedump),
	PHP_RSHUTDOWN(opcodedump),
	PHP_MINFO(opcodedump),
	PHP_OPCODEDUMP_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_OPCODEDUMP
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(opcodedump)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 */
