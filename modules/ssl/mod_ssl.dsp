# Microsoft Developer Studio Project File - Name="mod_ssl" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_ssl - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_ssl.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_ssl.mak" CFG="mod_ssl - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_ssl - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_ssl - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /I "../../include" /I "../../os/win32" /I "../../server/mpm/winnt" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fd"Release\mod_ssl" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /out:"Release/mod_ssl.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_ssl
# ADD LINK32 kernel32.lib ssleay32.lib libeay32.lib /nologo /libpath:"../../srclib/openssl/out32dll" /subsystem:windows /dll /incremental:no /map /out:"Release/mod_ssl.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_ssl

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /ZI /Od /I "../../include" /I "../../os/win32" /I "../../server/mpm/winnt" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fd"Debug\mod_ssl" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /out:"Debug/mod_ssl.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_ssl
# ADD LINK32 kernel32.lib ssleay32.lib libeay32.lib /nologo /libpath:"../../srclib/openssl/out32dll" /subsystem:windows /dll /incremental:no /map /debug /out:"Debug/mod_ssl.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_ssl

!ENDIF 

# Begin Target

# Name "mod_ssl - Win32 Release"
# Name "mod_ssl - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "*.c"
# Begin Source File

SOURCE=.\mod_ssl.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_config.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_dh.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_ds.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_ext.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_init.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_io.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_kernel.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_log.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_mutex.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_pphrase.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_rand.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_vars.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_eval.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_parse.c
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_scan.c
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\ssl_scache.c
# End Source File
# Begin Source File

SOURCE=.\ssl_scache_dbm.c
# End Source File
# Begin Source File

SOURCE=.\ssl_scache_shmcb.c
# End Source File
# Begin Source File

SOURCE=.\ssl_scache_shmht.c
# End Source File
# Begin Source File

SOURCE=.\ssl_util.c
# End Source File
# Begin Source File

SOURCE=.\ssl_util_ssl.c
# End Source File
# Begin Source File

SOURCE=.\ssl_util_table.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "*.h"
# Begin Source File

SOURCE=.\mod_ssl.h
# End Source File
# Begin Source File

SOURCE=.\ssl_expr.h
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_parse.h
# End Source File
# Begin Source File

SOURCE=.\ssl_util_ssl.h
# End Source File
# Begin Source File

SOURCE=.\ssl_util_table.h
# End Source File
# End Group
# End Target
# End Project
