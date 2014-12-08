@echo off

:shutdown_mysql
tasklist | find "mysqld.exe" > nul
if errorlevel 1 goto :uninstall_manifest
echo Shutting down mysqld.exe.
taskkill /f /im mysqld.exe

:uninstall_manifest
wevtutil gp MySQLWindowsAuditProvider 2> nul | find ":" > nul
if errorlevel 1 goto :install_manifest
echo Uninstall information manifest for MySQLWindowsAuditProvider
wevtutil um message.man

:install_manifest
echo Install manifest for MysQLWindowsAuditProvider
wevtutil im message.man

:copy dll file to plugin library
set mysql_plugin_dir="C:\Program Files\MySQL\MySQL Server 5.6\lib\plugin"
echo Copy %1 to %mysql_plugin_dir%
copy %1 %mysql_plugin_dir% > nul