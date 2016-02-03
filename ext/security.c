#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_security.h"

zend_function_entry security_functions[] = {
	PHP_FE(filtered_exec, NULL)
	PHP_FE(filtered_passthru, NULL)
	PHP_FE(filtered_system, NULL)
	PHP_FE(filtered_shell_exec, NULL)
	PHP_FE(filtered_popen, NULL)
	PHP_FE(filtered_proc_open, NULL)
};

zend_module_entry security_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"security",
	security_functions,
	PHP_MINIT(security),
	PHP_MSHUTDOWN(security),
	PHP_RINIT(security),
	PHP_RSHUTDOWN(security),
	PHP_MINFO(security),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_SECURITY_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SECURITY
ZEND_GET_MODULE(security)
#endif

// hooking stuff for: exec, passthru, shell_exec, system, proc_open, popen.
unsigned char jmps_ops[6][12] =
{
  "\x48\xB8\x20\x70\xC5\x6B\xD5\x7F\x00\x00\xFF\xE0",
  "\x48\xB8\x20\x70\xC5\x6B\xD5\x7F\x00\x00\xFF\xE0",
  "\x48\xB8\x20\x70\xC5\x6B\xD5\x7F\x00\x00\xFF\xE0",
  "\x48\xB8\x20\x70\xC5\x6B\xD5\x7F\x00\x00\xFF\xE0",
  "\x48\xB8\x20\x70\xC5\x6B\xD5\x7F\x00\x00\xFF\xE0",
  "\x48\xB8\x20\x70\xC5\x6B\xD5\x7F\x00\x00\xFF\xE0"
};

unsigned char ops_back[6][12];
unsigned char hook_lock[6] = { 0, 0, 0, 0, 0, 0 };

extern PHP_FUNCTION(exec);
extern PHP_FUNCTION(passthru);
extern PHP_FUNCTION(shell_exec);
extern PHP_FUNCTION(system);
extern PHP_FUNCTION(proc_open);
extern PHP_FUNCTION(popen);

void security_log(const char *fmt, ...)
{
	va_list arg;
	FILE *fh;

	fh = fopen("/tmp/php-security.log", "a");
	if(fh == NULL) return;
	/* Write the error message */
	va_start(arg, fmt);
	vfprintf(fh, fmt, arg);
	va_end(arg);
	fclose(fh);
}

int unhook_func(void *fname, unsigned int fid)
{
	int pgsz = getpagesize();
	int over = (unsigned long long)fname % pgsz;
	int iret;

	iret = mprotect(fname - over, pgsz, PROT_EXEC|PROT_READ|PROT_WRITE);
	if (iret != 0)
	{
		security_log("unhook_func(): mprotect() failed! 1\n");
		return -1;
	}
	memcpy(fname, ops_back[fid], 12);
	iret = mprotect(fname - over, pgsz, PROT_EXEC|PROT_READ);
	if (iret != 0)
	{
		security_log("unhook_func(): mprotect() failed! 2\n");
		return -1;
	}

	// mark this func as unhooked
	hook_lock[fid] = 0;

	return 0;
}

int allowed_execution()
{
	zval func_name, retval;
	ZVAL_STRING(&func_name, "security_is_execution_allowed");
	call_user_function_ex(EG(function_table), NULL, &func_name, &retval, 0, NULL, 0, NULL TSRMLS_CC);
	return Z_TYPE(retval) == IS_TRUE ? 0 : 1;
}

int hook_func(void *fname, void *ffname, unsigned int fid)
{
	/*int i;*/
	int pgsz, over, iret;

	// no re-hook if hooked.
	if (hook_lock[fid] == 1) return -1;
	hook_lock[fid] = 1;

	pgsz = getpagesize();
	// zero array of opcodes backup
	//memset(op_back, 0, sizoef(op_back));
	//exec = zend_hash_str_find_ptr(EG(function_table), "exec", 4);
	//printf("exec addr: %p\n", exec);
	// backup first 12 bytes of zif_exec into op_back
	memcpy(ops_back[fid], fname, 12);
	/*
	for(i = 0; i < sizeof(op_back) - 1; i++) {
	printf("%d: %x, ", i, op_back[i\]);
}
printf("\n");
printf("%p\n", exec);
printf("%p\n", filtered_exec);
*/
	// prepare jmp stuff with filtered_func() addr
	memcpy(jmps_ops[fid] + 2, &ffname, sizeof(ffname));
	/*
	for(i = 0; i < sizeof(jmp_op) - 1; i++) {
	printf("%d: %x, ", i, jmp_op[i]);
	}
	*/
	/*
	printf("\n");
	dl_iterate_phdr(callback, NULL);
	printf("%d %d\n", getpagesize(), mprotect(exec - 2272, getpagesize(), PROT_READ|PROT_WRITE|PROT_EXEC));
	printf("%d %s\n", errno, strerror(errno));
	*/
	over = (unsigned long long)fname % pgsz;
	iret = mprotect(fname - over, pgsz, PROT_EXEC|PROT_READ|PROT_WRITE);
	if (iret != 0)
	{
		security_log("hook_func(): mprotect() failed! 1.\n");
		return -1;
	}
	// hook fname func with jmp stuff
	memcpy(fname, jmps_ops[fid], 12);
	iret = mprotect(fname - over, pgsz, PROT_EXEC|PROT_READ);
	if (iret != 0)
	{
		security_log("hook_func(): mprotect() failed! 2.\n");
		return -1;
	}
	return 0;
}



PHP_FUNCTION(filtered_exec)
{
	//security_log("incoming vars: %p %p\n", execute_data, return_value);
  //printf("iNSiDe filtered_exec\n");
  if (allowed_execution() == 0)
  {
		//security_log("unhook at follows:");
    if (unhook_func(zif_exec, 0) == -1) {
			security_log("unhook_func(exec): fail.\n");
		}
		//security_log("zif_exec as follows:\n");
		zif_exec(INTERNAL_FUNCTION_PARAM_PASSTHRU);
		//security_log("hook_func as follows:");
    if (hook_func(zif_exec, zif_filtered_exec, 0) == -1)
		{
			security_log("hook_func(exec): fail\n");
		}
  }
}

PHP_FUNCTION(filtered_passthru)
{
	//security_log("incoming vars: %p %p\n", execute_data, return_value);
  //printf("iNSiDe filtered_exec\n");
  if (allowed_execution() == 0)
  {
		//security_log("unhook at follows:");
    if (unhook_func(zif_passthru, 1) == -1) {
			security_log("unhook_func(passthru): fail.\n");
		}
		//security_log("zif_exec as follows:\n");
		zif_passthru(INTERNAL_FUNCTION_PARAM_PASSTHRU);
		//security_log("hook_func as follows:");
    if (hook_func(zif_passthru, zif_filtered_passthru, 1) == -1)
		{
			security_log("hook_func(passthru): fail\n");
		}
  }
}

PHP_FUNCTION(filtered_system)
{
	//security_log("incoming vars: %p %p\n", execute_data, return_value);
  //printf("iNSiDe filtered_exec\n");
  if (allowed_execution() == 0)
  {
		//security_log("unhook at follows:");
    if (unhook_func(zif_system, 2) == -1) {
			security_log("unhook_func(system): fail.\n");
		}
		//security_log("zif_exec as follows:\n");
		zif_system(INTERNAL_FUNCTION_PARAM_PASSTHRU);
		//security_log("hook_func as follows:");
    if (hook_func(zif_system, zif_filtered_system, 2) == -1)
		{
			security_log("hook_func(system): fail\n");
		}
  }
}

PHP_FUNCTION(filtered_shell_exec)
{
	//security_log("incoming vars: %p %p\n", execute_data, return_value);
  //printf("iNSiDe filtered_exec\n");
  if (allowed_execution() == 0)
  {
		//security_log("unhook at follows:");
    if (unhook_func(zif_shell_exec, 3) == -1) {
			security_log("unhook_func(shell_exec): fail.\n");
		}
		//security_log("zif_exec as follows:\n");
		zif_shell_exec(INTERNAL_FUNCTION_PARAM_PASSTHRU);
		//security_log("hook_func as follows:");
    if (hook_func(zif_shell_exec, zif_filtered_shell_exec, 3) == -1)
		{
			security_log("hook_func(shell_exec): fail\n");
		}
  }
}

PHP_FUNCTION(filtered_proc_open)
{
	//security_log("incoming vars: %p %p\n", execute_data, return_value);
  //printf("iNSiDe filtered_exec\n");
  if (allowed_execution() == 0)
  {
		//security_log("unhook at follows:");
    if (unhook_func(zif_proc_open, 4) == -1) {
			security_log("unhook_func(proc_open): fail.\n");
		}
		//security_log("zif_exec as follows:\n");
		zif_proc_open(INTERNAL_FUNCTION_PARAM_PASSTHRU);
		//security_log("hook_func as follows:");
    if (hook_func(zif_proc_open, zif_filtered_proc_open, 4) == -1)
		{
			security_log("hook_func(proc_open): fail\n");
		}
  }
}

PHP_FUNCTION(filtered_popen)
{
	//security_log("incoming vars: %p %p\n", execute_data, return_value);
  //printf("iNSiDe filtered_exec\n");
  if (allowed_execution() == 0)
  {
		//security_log("unhook at follows:");
    if (unhook_func(zif_popen, 5) == -1) {
			security_log("unhook_func(popen): fail.\n");
		}
		//security_log("zif_exec as follows:\n");
		zif_popen(INTERNAL_FUNCTION_PARAM_PASSTHRU);
		//security_log("hook_func as follows:");
    if (hook_func(zif_popen, zif_filtered_popen, 5) == -1)
		{
			security_log("hook_func(popen): fail\n");
		}
  }
}

int install_hooks()
{
  if (hook_func(zif_exec, zif_filtered_exec, 0) == 0 &&
  hook_func(zif_passthru, zif_filtered_passthru, 1) == 0 &&
  hook_func(zif_system, zif_filtered_system, 2) == 0 &&
  hook_func(zif_shell_exec, zif_filtered_shell_exec, 3) == 0 &&
  hook_func(zif_proc_open, zif_filtered_proc_open, 4) == 0 &&
  hook_func(zif_popen, zif_filtered_popen, 5) == 0)
  {
    return 0;
  }

  return -1;
}

int uninstall_hooks()
{
  if (unhook_func(zif_exec, 0) == 0 &&
  unhook_func(zif_passthru, 1) == 0 &&
  unhook_func(zif_system, 2) == 0 &&
  unhook_func(zif_shell_exec, 3) == 0 &&
  unhook_func(zif_proc_open, 4) == 0 &&
  unhook_func(zif_popen, 5) == 0)
  {
    return 0;
  }

  return -1;
}

PHP_MINIT_FUNCTION(security)
{
	security_log("install_hooks:");
	if (install_hooks() == 0)
	{
		security_log("success\n");
		return SUCCESS;
	}
	else
	{
		security_log("fail\n");
		return FAILURE;
	}
}

PHP_MSHUTDOWN_FUNCTION(security)
{
	security_log("uninstall_hooks:");
	if (uninstall_hooks() == 0)
	{
		security_log("success\n");
		return SUCCESS;
	}
	else
	{
		security_log("fail\n");
		return FAILURE;
	}
}

PHP_RINIT_FUNCTION(security)
{
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(security)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(security)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "Option", "Value");
	php_info_print_table_row(2, "Version", PHP_SECURITY_VERSION);
	php_info_print_table_row(2, "Whitelisted functions", "exec, passthru, system, shell_exec, popen and proc_open");
	php_info_print_table_row(2, "Author", "Devopensource Security Team");
	php_info_print_table_end();
}
