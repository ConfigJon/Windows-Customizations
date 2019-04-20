@ECHO OFF

REM Set a current working directory variable
set loc=%~dp0

REM Replace the Default User Profile image
copy /y "%loc%user.bmp" "%programdata%\Microsoft\User Account Pictures\"