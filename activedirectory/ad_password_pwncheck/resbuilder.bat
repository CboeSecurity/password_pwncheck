wevtutil um pwncheck_winevent_resources.man
mc pwncheck_winevent_resources.man
rc pwncheck_winevent_resources.rc
link -dll -noentry pwncheck_winevent_resources.res
'wevtutil im Resources.man /rf:"c:\nresource.dll" /mf:"c:\nresource.dll"