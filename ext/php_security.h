#ifndef PHP_SECURITY_H
#define PHP_SECURITY_H 1

#define PHP_SECURITY_VERSION "1.0"
#define PHP_SECURITY_EXTNAME "security"

#include <sys/mman.h>

PHP_FUNCTION(filtered_exec);
PHP_FUNCTION(filtered_passthru);
PHP_FUNCTION(filtered_shell_exec);
PHP_FUNCTION(filtered_system);
PHP_FUNCTION(filtered_popen);
PHP_FUNCTION(filtered_proc_open);
PHP_MINIT_FUNCTION(security);
PHP_MSHUTDOWN_FUNCTION(security);
PHP_RINIT_FUNCTION(security);
PHP_RSHUTDOWN_FUNCTION(security);
PHP_MINFO_FUNCTION(security);

extern zend_module_entry security_module_entry;
#define phpext_security_ptr &security_module_entry

#endif
