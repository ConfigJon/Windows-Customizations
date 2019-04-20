@ECHO OFF

REM Set a current working directory variable
set loc=%~dp0

REM Replace the Default Lock Screen image
copy /y "%loc%LockScreenimage.jpg" "%Windir%\Web\Screen"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "LockScreenImage" /t REG_SZ /d "%Windir%\Web\Screen\LockScreenImage.jpg" /f