# What is php-security ?

![alt tag](https://drive.google.com/file/d/0B4EKL_0QRk-cOF9Jd3lwQ09TUnM/view?usp=sharing)


This package is composed by two parts of difference:

1. Extension in C
2. PHP routines for controlling the shell executions.

The functionality of this software is to hook each php function which allows
the execution of shell commands, they are: system, exec, passthru, shell_exec,
popen and proc_open. If you know someone else you can send me an email:
abel.romero [at] devopensource.com.

By hooking those functions, we can control the execution of those named.
When an script calls some of those ones, we get inside a function in a file
called: prepend.php. Which will be loaded on each php execution by a directive
in the security.ini file. This function is called security_is_execution_allowed().
And it's inside the directory named php/ .

There's also a library for logging the intentionallities of execute commands,
which supports posting on #Slack and syslog of the linux os.

The module should appear on phpinfo() webpage if it's succesfully loaded.

You should install php/ directory inside a root managed directory,
but you can include inside the php library of your vhost. Another option
is to define the directory into the include_dir directive, but the path is hardcoded to /etc/php/mods-available/security/prepend.php .

Once the hooked function is called, the execution flow is redirected to a 
another function by a jmp injection inside its content. And those functions
are dedicated to each hooked one. Those for shell execution, are already
coded and they are: filtered_exec, filtered_system, etc.

The unhook_func() is called, to restore the opcodes. When the function in
question is restored, a call is made to the real function. But before
the whitelist is queried for allowing or denying the execution.

Another file inside php/ is the whitelist.php. Which has an array where
the absolute paths of the php scripts which are allowed to execute, are defined.

Then the function is re-hooked.

If an script calls those hooked functions, and the path of the script is not
inside the whitelist array, it'll log in #slack or in syslog.
You should have a look to the php/ functions.

In the first time you should generate the extension scripts and files.
Then install the .ini of the mod, and copy it to libraries path.

Finally put the php/ directory contents inside the hardcoded path:

/etc/php/mods-available/security/

... prepend.php

... whitelist.php

... slacklog.php

... ..

... .


#### How to compile the extension ?

git clone https://github.com/aberope/php-security.git

cd php-security/ext

make clean

phpize

./configure

make

#### How to enable the extension

sudo cp ini/security.ini /etc/php/mods-available

sudo mkdir /etc/php/mods-available/security

sudo cp whitelist.php prepend.php slackbot.php /etc/php/mods-available/security

##### Note: use apache2 installation dir

sudo ln -s /etc/php/mods-available/security.ini /etc/php/7.0/apache2/conf.d/20-security.ini

sudo cp ext/modules/security.so /usr/lib/php/20151012/ 

#### Managing whitelist

Edit /etc/php/mods-available/security/whitelist.php and add the corresponding files to be allowed.

Any else execution not called from those files in $whitelist, will be logged and blocked.

#### Watching Logs

For watching the logs, you can just connect to slack and change the URL
for the posting, or execute the following command which takes the logs
from the syslog file:

tail -f  /var/log/syslog | grep php-security

