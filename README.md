# What is php-security ?

![alt tag](https://raw.githubusercontent.com/aberope/php-security/master/PHP%20Security%20Architecture%20(1).png)


This package is composed by two parts:

1. C lang extension for PHP 7
2. PHP Routines for filtering shell command execution and logging/notification.

The functionality of this software is to hook each php function which allows
the execution of shell commands, they are: `system`, `exec`, `passthru`, `shell_exec`,
`popen` and `proc_open`. If you know some other else you can send me an email to:
`abel [at] abelromero.com`.

By hooking those functions, we can control the execution of those named.
When an script calls some of those ones, we get inside a function in a file
called: `php/prepend.php`. Which will be loaded on each PHP execution by a directive
in the `security.ini` file. This function is called `security_is_execution_allowed()`.
And it's inside the directory named php/ .

There's also a library for logging the intentionallities of execute commands,
which supports posting on `#Slack` and syslog of the linux os.

The module should appear on `phpinfo()` webpage if it's succesfully loaded.

You should install `php/` directory inside a root user managed directory,
but you can include inside the php library of your vhost... another option
is to define the directory into the `include_dir` directive, but the path is hardcoded to `/etc/php/mods-available/security/prepend.php`.

Once the hooked function is called, the execution flow is redirected to a 
another function by a `jmp`. And those functions
are dedicated to each hooked one. Those for shell execution, are already
coded and they are: `filtered_exec`, `filtered_system`, etc.

The `unhook_func()` is called, to restore the opcodes, and should be removed in newer versions as described in `TODO`, because it's not well done. 

When the function in question is restored, a call is made to the real function, but will be replaced by a trampoline in a future version. Before calling or not the shell execution command function, the `whitelist` is queried for allowing or denying the execution.

Another file is `php/whitelist.php`. Which has an array where
the absolute paths of the php scripts which are allowed to execute, are defined. Here you must define carefully each script
which is able to execute shell commands, and I recommend you that an `IT Security expert` helps you to pentest those scripts, before whitelisting them, if you are going to use this module.

Then the function is re-hooked. (But that shouldn't happen on first release).

If an script calls those hooked functions, and the path of the script is not
inside the whitelist array, it'll log in `#Slack` or in  `syslog`. Depending on your needs, you can comment the corresponding lines in `php/prepend.php`. Have a look to the functions on this file, to configure the behaivour of this module.

In the first time you should generate the extension scripts and files.
Then install the `security.ini` of the mod, and copy it to libraries path.

Finally put the `php/` directory contents inside the hardcoded path:

`/etc/php/mods-available/security/`
`prepend.php`
`whitelist.php`
`slacklog.php`

#### How to compile the extension ?
```
git clone https://github.com/aberope/php-security.git
cd php-security/ext
make clean
phpize
./configure
make
```

#### How to enable the extension
```
sudo cp ini/security.ini /etc/php/mods-available
sudo mkdir /etc/php/mods-available/security
sudo cp whitelist.php prepend.php slackbot.php /etc/php/mods-available/security
```
##### Note: use apache2 installation dir
```
sudo ln -s /etc/php/mods-available/security.ini /etc/php/7.0/apache2/conf.d/20-security.ini
sudo cp ext/modules/security.so /usr/lib/php/20151012/
```
#### Managing whitelist

Edit `/etc/php/mods-available/security/whitelist.php` and add the corresponding files to be allowed.

Any else execution not called from those files in `$whitelist`, will be logged and blocked.

#### Watching Logs

For watching the logs, you can just connect to slack and change the URL
for the posting, or execute the following command which takes the logs
from the syslog file:

`tail -f  /var/log/syslog | grep php-security`



Hope this helps.
