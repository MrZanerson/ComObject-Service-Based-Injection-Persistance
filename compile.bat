@ECHO OFF

cl.exe /W0 /D_USRDLL /D_WINDLL  /Tp *.cpp WorkFoldersShell.def /MT /link /DLL /OUT:WrkFoldersShell.dll