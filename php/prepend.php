<?php

include_once '/etc/php/mods-available/security/slackbot.php';

function security_get_current_stack() {
  $stack = debug_backtrace();
  return $stack[count($stack) - 1];
}

function security_is_execution_allowed()
{
  //echo "from filter\n";

  // array of allowed files
  include '/etc/php/mods-available/security/whitelist.php';
  // get current stack position
  $stack = security_get_current_stack();
  $file = $stack['file'];
  // check between whitelist
  if (in_array($file, $whitelist)) {
    return true;
  }
  // log fail Attempt
  $log = "php-security: ".
  "the following file tried to execute (a) shell command(s): ". 
  $file . PHP_EOL;
  //error_log($log, 1, $admin);
  //error_log($log, 0);
  syslog(LOG_WARNING, $log);
  slackbot_log($log);
  // deny execution
  return false;
}
?>
