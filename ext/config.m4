dnl $Id$
dnl config.m4 for extension security

PHP_ARG_ENABLE(security, whether to enable security support,
[  --enable-security           Enable security support], no, yes)


if test "$PHP_SECURITY" != "no"; then
  PHP_NEW_EXTENSION(security, security.c, $ext_shared,, -Wdeclaration-after-statement -Werror -Wall -Wno-deprecated-declarations)
fi
