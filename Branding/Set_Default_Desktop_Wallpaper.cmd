@ECHO OFF

REM Set a current working directory variable
set loc=%~dp0

REM Replace the Default Wallpaper

REM Take ownership of the default wallpaper files
takeown /f "%windir%\WEB\wallpaper\Windows\img0.jpg"
takeown /f "%windir%\Web\4K\Wallpaper\Windows\*.*"
icacls "%windir%\WEB\wallpaper\Windows\img0.jpg" /Grant System:(F)
icacls "%windir%\Web\4K\Wallpaper\Windows\*.*" /Grant System:(F)

REM Delete the original wallpaper files
del /q "%windir%\WEB\wallpaper\Windows\img0.jpg"
del /q "%windir%\Web\4K\Wallpaper\Windows\*.*"

REM Copy the new wallpaper files
copy "%loc%img0.jpg" "%windir%\WEB\wallpaper\Windows\img0.jpg"
xcopy "%loc%4k\*.*" "%windir%\Web\4K\Wallpaper\Windows" /Y