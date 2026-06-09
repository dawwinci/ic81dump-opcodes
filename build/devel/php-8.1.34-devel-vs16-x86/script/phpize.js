var PHP_PREFIX="C:\\php"
var PHP_ZTS="No"
var VC_VERSION=1929
var PHP_VERSION=8
var PHP_MINOR_VERSION=1
var PHP_RELEASE_VERSION=34
var PHP_EXTRA_VERSION=""
var PHP_VERSION_STRING="8.1.34"

/* Generated extensions list with mode (static/shared) */
PHP_BCMATH_SHARED=false;
PHP_BZ2_SHARED=true;
PHP_CALENDAR_SHARED=false;
PHP_COM_DOTNET_SHARED=true;
PHP_CTYPE_SHARED=false;
PHP_CURL_SHARED=true;
PHP_DATE_SHARED=false;
PHP_DBA_SHARED=true;
PHP_DL_TEST_SHARED=true;
PHP_ENCHANT_SHARED=true;
PHP_FFI_SHARED=true;
PHP_FILEINFO_SHARED=true;
PHP_FILTER_SHARED=false;
PHP_FTP_SHARED=true;
PHP_GD_SHARED=true;
PHP_GETTEXT_SHARED=true;
PHP_GMP_SHARED=true;
PHP_HASH_SHARED=false;
PHP_ICONV_SHARED=false;
PHP_IMAP_SHARED=true;
PHP_INTL_SHARED=true;
PHP_JSON_SHARED=false;
PHP_LDAP_SHARED=true;
PHP_MBSTRING_SHARED=true;
PHP_MYSQLND_SHARED=false;
PHP_OCI8_19_SHARED=true;
PHP_ODBC_SHARED=true;
PHP_OPCACHE_SHARED=true;
PHP_OPENSSL_SHARED=true;
PHP_PCRE_SHARED=false;
PHP_PGSQL_SHARED=true;
PHP_READLINE_SHARED=false;
PHP_REFLECTION_SHARED=false;
PHP_SESSION_SHARED=false;
PHP_SHMOP_SHARED=true;
PHP_SNMP_SHARED=true;
PHP_SOCKETS_SHARED=true;
PHP_SODIUM_SHARED=true;
PHP_SPL_SHARED=false;
PHP_SQLITE3_SHARED=true;
PHP_STANDARD_SHARED=false;
PHP_SYSVSHM_SHARED=true;
PHP_TIDY_SHARED=true;
PHP_TOKENIZER_SHARED=false;
PHP_ZEND_TEST_SHARED=true;
PHP_ZIP_SHARED=false;
PHP_ZLIB_SHARED=false;
PHP_LIBXML_SHARED=false;
PHP_DOM_SHARED=false;
PHP_EXIF_SHARED=true;
PHP_MYSQLI_SHARED=true;
PHP_PDO_SHARED=false;
PHP_PDO_FIREBIRD_SHARED=true;
PHP_PDO_MYSQL_SHARED=true;
PHP_PDO_OCI_SHARED=true;
PHP_PDO_ODBC_SHARED=true;
PHP_PDO_PGSQL_SHARED=true;
PHP_PDO_SQLITE_SHARED=true;
PHP_PHAR_SHARED=false;
PHP_SIMPLEXML_SHARED=false;
PHP_SOAP_SHARED=true;
PHP_XML_SHARED=false;
PHP_XMLREADER_SHARED=false;
PHP_XMLWRITER_SHARED=false;
PHP_XSL_SHARED=true;


/* Generated win32/build/phpize.js.in */

/*
  +----------------------------------------------------------------------+
  | Copyright (c) The PHP Group                                          |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | https://www.php.net/license/3_01.txt                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Pierre Joye <pierre1@php.net>                                |
  +----------------------------------------------------------------------+
*/

// This generates a configure script for win32 build

var STDOUT = WScript.StdOut;

var FSO = WScript.CreateObject("Scripting.FileSystemObject");
var C = FSO.CreateTextFile("configure.js", true);
var B = FSO.CreateTextFile("configure.bat", true);
re = /\\script/i;
var PHP_DIR=FSO.GetParentFolderName(WScript.ScriptFullName).replace(re,"");

var modules = "";
var MODULES = WScript.CreateObject("Scripting.Dictionary");
var module_dirs = new Array();

function ERROR(msg)
{
	STDERR.WriteLine("ERROR: " + msg);
	WScript.Quit(3);
}

function file_get_contents(filename)
{
	var t = "";
	var F = FSO.OpenTextFile(filename, 1);

	if (!F.AtEndOfStream) {
		t = F.ReadAll();
		F.Close();
	}
	return t;
}

function Module_Item(module_name, config_path, dir_line, deps, content)
{
	this.module_name = module_name;
	this.config_path = config_path;
	this.dir_line = dir_line;
	this.deps = deps;
	this.content = content;
}

function get_module_dep(contents)
{
	var re_dep_line = new RegExp("ADD_EXTENSION_DEP\\([^,]*\\s*,\\s*['\"]([^'\"]+)['\"].*\\)", "gm");
	var calls = contents.match(re_dep_line);
	var deps = new Array();
	if (calls != null) {
		for (i = 0; i < calls.length; i++) {
			// now we need the extension name out of this thing
			if (calls[i].match(re_dep_line)) {
				deps[deps.length] = RegExp.$1;

			}
		}
	}
	return deps;
}

function find_config_w32(dirname)
{
	if (!FSO.FolderExists(dirname)) {
		return;
	}

	var f = FSO.GetFolder(dirname);
	var	fc = new Enumerator(f.SubFolders);
	var c, i, ok, n;
	var item = null;

	c = dirname + "\\config.w32";
	if (FSO.FileExists(c)) {
		var dir_line = "configure_module_dirname = condense_path(FSO.GetParentFolderName('"
								+ c.replace(new RegExp('(["\\\\])', "g"), '\\$1') + "'));\r\n";
		var contents = file_get_contents(c);

		deps = get_module_dep(contents);

		n = "";
		item = new Module_Item(n, c, dir_line, deps, contents);
		MODULES.Add(n, item);
	}

	for (; !fc.atEnd(); fc.moveNext()) {
		/* check if we already picked up a module with the same dirname;
		 * if we have, don't include it here */
		n = FSO.GetFileName(fc.item());
		if (n == '.svn' || n == 'tests' || n == '.git') {
			continue;
		}

		c = FSO.BuildPath(fc.item(), "config.w32");
		if (FSO.FileExists(c)) {
			var dir_line = "configure_module_dirname = condense_path(FSO.GetParentFolderName('"
							   	+ c.replace(new RegExp('(["\\\\])', "g"), '\\$1') + "'));\r\n";
			var contents = file_get_contents(c);

			deps = get_module_dep(contents);

			item = new Module_Item(n, c, dir_line, deps, contents);
			MODULES.Add(n, item);
		}
	}
}

function emit_module(item)
{
	return item.dir_line + item.content;
}

function emit_dep_modules(module_names)
{
	var i, mod_name, j;
	var output = "";
	var item = null;

	for (i in module_names) {
		mod_name = module_names[i];

		if (MODULES.Exists(mod_name)) {
			item = MODULES.Item(mod_name);
			MODULES.Remove(mod_name);
			if (item.deps.length) {
				output += emit_dep_modules(item.deps);
			}
			output += emit_module(item);
		}
	}

	return output;
}

function gen_modules()
{
	var module_names = (new VBArray(MODULES.Keys())).toArray();
	var i, mod_name, j;
	var item;
	var output = "";

	// first, look for modules with empty deps; emit those first
	for (i in module_names) {
		STDOUT.WriteLine("module ... " + module_names);
		mod_name = module_names[i];
		item = MODULES.Item(mod_name);
		if (item.deps.length == 0) {
			MODULES.Remove(mod_name);
			output += emit_module(item);
		}
	}

	// now we are left with modules that have dependencies on other modules
	module_names = (new VBArray(MODULES.Keys())).toArray();
	output += emit_dep_modules(module_names);

	return output;
}

// Process buildconf arguments
function buildconf_process_args()
{
	args = WScript.Arguments;

	for (i = 0; i < args.length; i++) {
		arg = args(i);
		// If it is --foo=bar, split on the equals sign
		arg = arg.split("=", 2);
		argname = arg[0];
		if (arg.length > 1) {
			argval = arg[1];
		} else {
			argval = null;
		}

		if (argname == '--clean' && argval != null) {
			STDOUT.WriteLine("Cleaning...");
			return 0;
		}

		if (argname == '--help') {
			STDOUT.WriteLine("Usage: phpize [--clean|--help|--version|-v]");
			return 0;
		}
		return 1;
	}
}

if (buildconf_process_args() == 0) {
	WScript.Quit(3);
}
STDOUT.WriteLine("Rebuilding configure.js");
STDOUT.WriteLine(PHP_DIR);

// Write the head of the configure script
C.WriteLine("/* This file automatically generated from script/confutils.js */");
C.WriteLine("var MODE_PHPIZE = true;");
C.WriteLine("var PHP_DIR = " + '"' + PHP_DIR.replace(new RegExp('(["\\\\])', "g"), '\\$1') + '"');
C.WriteLine("var PHP_PREFIX = " + '"' + PHP_PREFIX.replace(new RegExp('(["\\\\])', "g"), '\\$1') + '"');

/* XXX this needs to be implemented for the phpize mode yet, a quick fix just to disable it for now */
C.WriteLine("var PHP_ANALYZER = 'disabled';");
C.WriteLine("var PHP_PGO = 'no';");
C.WriteLine("var PHP_PGI = 'no';");

C.WriteLine("var PHP_VERSION=" + PHP_VERSION);
C.WriteLine("var PHP_MINOR_VERSION=" + PHP_MINOR_VERSION);
C.WriteLine("var PHP_RELEASE_VERSION=" + PHP_RELEASE_VERSION);
C.WriteLine("var PHP_EXTRA_VERSION=\"" + PHP_EXTRA_VERSION + "\"");
C.WriteLine("var PHP_VERSION_STRING=\"" + PHP_VERSION_STRING + "\"");

C.Write(file_get_contents(PHP_DIR + "//script//ext_deps.js"));
if (FSO.FileExists(PHP_DIR + "/script/ext_pickle.js")) {
	C.Write(file_get_contents(PHP_DIR + "//script//ext_pickle.js"));
}

C.Write(file_get_contents(PHP_DIR + "/script/confutils.js"));
C.Write(file_get_contents(PHP_DIR + "/script/config.phpize.js"));

// Pull in code for the base detection
modules = file_get_contents(PHP_DIR + "/script/config.w32.phpize.in");

C.WriteLine("ARG_ENABLE('debug', 'Compile with debugging symbols', PHP_DEBUG);");
find_config_w32(".");

// Now generate contents of module based on MODULES, chasing dependencies
// to ensure that dependent modules are emitted first
modules += gen_modules();

// Look for ARG_ENABLE or ARG_WITH calls
re = new RegExp("(ARG_(ENABLE|WITH)\([^;]+\);)", "gm");
calls = modules.match(re);
for (i = 0; i < calls.length; i++) {
	item = calls[i];
	C.WriteLine("try {");
	C.WriteLine(item);
	C.WriteLine("} catch (e) {");
	C.WriteLine('\tSTDOUT.WriteLine("problem: " + e);');
	C.WriteLine("}");
}

C.WriteBlankLines(1);
C.WriteLine("conf_process_args();");
C.WriteBlankLines(1);

// Comment out the calls from their original positions
modules = modules.replace(re, "/* $1 */");
C.Write(modules);


C.WriteBlankLines(1);
C.Write(file_get_contents(PHP_DIR + "\\script\\configure.tail"));

B.WriteLine("@echo off");
B.WriteLine("cscript /nologo /e:jscript configure.js %*");

FSO.CopyFile(PHP_DIR + "\\script\\run-tests.php", "run-tests.php", true);
