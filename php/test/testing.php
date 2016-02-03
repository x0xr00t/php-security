<?php

echo "php-security Test\n";

for ($i = 0; $i < 250; $i++)
	test_all_functions();

function test_all_functions() {
  echo "exec:\n";
  echo exec("id");
  echo "\n";
  echo "passthru:\n";
  echo passthru("id");
  echo "\n";
  echo "shell_exec:\n";
  echo shell_exec("id");
  echo "\n";
  echo "system:\n";
  echo system("id");
  echo "\n";
  echo "proc_open:\n";
  $cwd='/tmp';
  $descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("file", "php://stdout", "a") );

    $process = proc_open("id", $descriptorspec, $pipes, $cwd);
    if ($process) {
      echo stream_get_contents($pipes[1]);
      fclose($pipes[1]);
    }
    echo "\n";
    echo "popen:\n";
    $gestor = popen('id', 'r');
    if ($gestor != null){
      $leer = fread($gestor, 2096);
      echo $leer;
      pclose($gestor);
    }
    echo "\n";
}

?>
