# Microsoft Developer Studio Project File - Name="Apache" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=Apache - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Apache.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Apache.mak" CFG="Apache - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Apache - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "Apache - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Apache - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ".\ApacheLa"
# PROP BASE Intermediate_Dir ".\ApacheLa"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".\ApacheR"
# PROP Intermediate_Dir ".\ApacheR"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "./include" /I "./lib/apr/include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "WIN32_LEAN_AND_MEAN" /FD /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 aprlib.lib ApacheCore.lib kernel32.lib advapi32.lib /nologo /subsystem:console /map /machine:I386 /libpath:"lib\apr\Release" /libpath:"CoreR"
# ADD LINK32 aprlib.lib ApacheCore.lib kernel32.lib advapi32.lib user32.lib /nologo /subsystem:console /map /machine:I386 /libpath:"lib\apr\Release" /libpath:"CoreR"

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ".\ApacheL0"
# PROP BASE Intermediate_Dir ".\ApacheL0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\ApacheD"
# PROP Intermediate_Dir ".\ApacheD"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "./include" /I "./lib/apr/include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "WIN32_LEAN_AND_MEAN" /FD /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 aprlib.lib ApacheCore.lib kernel32.lib advapi32.lib /nologo /subsystem:console /map /debug /machine:I386 /libpath:"lib\apr\debug" /libpath:"CoreD"
# ADD LINK32 aprlib.lib ApacheCore.lib kernel32.lib advapi32.lib user32.lib /nologo /subsystem:console /debug /machine:I386 /libpath:"lib\apr\debug" /libpath:"CoreD"
# SUBTRACT LINK32 /incremental:no /map

!ENDIF 

# Begin Target

# Name "Apache - Win32 Release"
# Name "Apache - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Source File

SOURCE=.\os\win32\main_win32.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\registry.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\service.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;fi;fd"
# Begin Source File

SOURCE=.\OS\WIN32\main_win32.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\registry.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\service.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;cnt;rtf;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\os\win32\apache.ico
# End Source File
# Begin Source File

SOURCE=.\os\win32\apache.rc
# End Source File
# End Group
# End Target
# End Project
