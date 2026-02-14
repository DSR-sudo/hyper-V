@echo off
setlocal

mountvol Z: /S

set boot_directory=Z:\EFI\Microsoft\Boot\

if exist "%boot_directory%bootmgfw.original.efi" (
    echo hyper-reV seems to be already scheduled
) else (
    attrib -s %boot_directory%bootmgfw.efi
    move %boot_directory%bootmgfw.efi %boot_directory%bootmgfw.original.efi

    copy /Y %~dp0uefi-boot.efi %boot_directory%bootmgfw.efi
    copy /Y %~dp0hyperv-attachment.dll %boot_directory%

    

    echo hyper-reV will load at next boot
)

endlocal
pause