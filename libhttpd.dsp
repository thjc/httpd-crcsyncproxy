# Microsoft Developer Studio Project File - Name="libhttpd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libhttpd - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libhttpd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libhttpd.mak" CFG="libhttpd - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libhttpd - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libhttpd - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libhttpd - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /I ".\include" /I ".\srclib\apr\include" /I ".\srclib\apr-util\include" /I "./server/mpm/winnt" /I "./srclib/expat-lite" /I "./os/win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /I ".\include" /I ".\srclib\apr\include" /I ".\srclib\apr-util\include" /I "./server/mpm/winnt" /I "./srclib/expat-lite" /I "./os/win32" /I "./modules/http" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /Fd"Release\libhttpd" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /map /machine:I386 /base:@"os\win32\BaseAddr.ref",libhttpd
# ADD LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /map /machine:I386 /base:@"os\win32\BaseAddr.ref",libhttpd

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Od /I ".\include" /I ".\srclib\apr\include" /I ".\srclib\apr-util\include" /I "./server/mpm/winnt" /I "./srclib/expat-lite" /I "./os/win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /FD /ZI /c
# ADD CPP /nologo /MDd /W3 /GX /Od /I ".\include" /I ".\srclib\apr\include" /I ".\srclib\apr-util\include" /I "./server/mpm/winnt" /I "./srclib/expat-lite" /I "./os/win32" /I "./modules/http" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /Fd"Debug\libhttpd" /FD /ZI /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /machine:I386 /base:@"os\win32\BaseAddr.ref",libhttpd
# ADD LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /machine:I386 /base:@"os\win32\BaseAddr.ref",libhttpd

!ENDIF 

# Begin Target

# Name "libhttpd - Win32 Release"
# Name "libhttpd - Win32 Debug"
# Begin Group "core"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Source File

SOURCE=.\include\ap_config.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_mmn.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_release.h
# End Source File
# Begin Source File

SOURCE=.\server\buildmark.c
# End Source File
# Begin Source File

SOURCE=.\server\config.c
# End Source File
# Begin Source File

SOURCE=.\server\connection.c
# End Source File
# Begin Source File

SOURCE=.\include\http_conf_globals.h
# End Source File
# Begin Source File

SOURCE=.\include\http_config.h
# End Source File
# Begin Source File

SOURCE=.\include\http_connection.h
# End Source File
# Begin Source File

SOURCE=.\include\http_log.h
# End Source File
# Begin Source File

SOURCE=.\include\http_main.h
# End Source File
# Begin Source File

SOURCE=.\include\http_vhost.h
# End Source File
# Begin Source File

SOURCE=.\include\httpd.h
# End Source File
# Begin Source File

SOURCE=.\server\log.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\modules.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\os.h
# End Source File
# Begin Source File

SOURCE=.\server\scoreboard.c
# End Source File
# Begin Source File

SOURCE=.\server\vhost.c
# End Source File
# End Group
# Begin Group "generated"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\server\gen_test_char.exe

!IF  "$(CFG)" == "libhttpd - Win32 Release"

# Begin Custom Build - Generating test_char.h
InputPath=.\server\gen_test_char.exe

".\server\test_char.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_test_char.exe >.\server\test_char.h 
	echo Generated test_char.h from gen_test_char.exe 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

# Begin Custom Build - Generating test_char.h
InputPath=.\server\gen_test_char.exe

".\server\test_char.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_test_char.exe >.\server\test_char.h 
	echo Generated test_char.h from gen_test_char.exe 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\server\test_char.h
# End Source File
# End Group
# Begin Group "httpd"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\modules\http\http_core.c
# End Source File
# Begin Source File

SOURCE=.\include\http_core.h
# End Source File
# Begin Source File

SOURCE=.\modules\http\http_protocol.c
# End Source File
# Begin Source File

SOURCE=.\include\http_protocol.h
# End Source File
# Begin Source File

SOURCE=.\modules\http\http_request.c
# End Source File
# Begin Source File

SOURCE=.\include\http_request.h
# End Source File
# End Group
# Begin Group "modules"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\modules\aaa\mod_access.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_actions.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_alias.c
# End Source File
# Begin Source File

SOURCE=.\modules\generators\mod_asis.c
# End Source File
# Begin Source File

SOURCE=.\modules\aaa\mod_auth.c
# End Source File
# Begin Source File

SOURCE=.\modules\generators\mod_autoindex.c
# End Source File
# Begin Source File

SOURCE=.\modules\generators\mod_cgi.c
# End Source File
# Begin Source File

SOURCE=.\modules\http\mod_core.h
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_dir.c
# End Source File
# Begin Source File

SOURCE=.\modules\metadata\mod_env.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_imap.c
# End Source File
# Begin Source File

SOURCE=.\modules\filters\mod_include.c
# End Source File
# Begin Source File

SOURCE=.\modules\filters\mod_include.h
# End Source File
# Begin Source File

SOURCE=.\modules\arch\win32\mod_isapi.c
# End Source File
# Begin Source File

SOURCE=.\modules\loggers\mod_log_config.c
# End Source File
# Begin Source File

SOURCE=.\modules\http\mod_mime.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_negotiation.c
# End Source File
# Begin Source File

SOURCE=.\modules\metadata\mod_setenvif.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_so.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_userdir.c
# End Source File
# End Group
# Begin Group "util"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\server\core.c
# End Source File
# Begin Source File

SOURCE=.\server\error_bucket.c
# End Source File
# Begin Source File

SOURCE=.\server\protocol.c
# End Source File
# Begin Source File

SOURCE=.\server\request.c
# End Source File
# Begin Source File

SOURCE=.\server\rfc1413.c
# End Source File
# Begin Source File

SOURCE=.\include\rfc1413.h
# End Source File
# Begin Source File

SOURCE=.\server\util.c
# End Source File
# Begin Source File

SOURCE=.\server\util_cfgtree.c
# End Source File
# Begin Source File

SOURCE=.\include\util_cfgtree.h
# End Source File
# Begin Source File

SOURCE=.\include\util_charset.h
# End Source File
# Begin Source File

SOURCE=.\server\util_date.c
# End Source File
# Begin Source File

SOURCE=.\include\util_date.h
# End Source File
# Begin Source File

SOURCE=.\include\util_ebcdic.h
# End Source File
# Begin Source File

SOURCE=.\server\util_filter.c
# End Source File
# Begin Source File

SOURCE=.\include\util_filter.h
# End Source File
# Begin Source File

SOURCE=.\server\util_md5.c
# End Source File
# Begin Source File

SOURCE=.\include\util_md5.h
# End Source File
# Begin Source File

SOURCE=.\server\util_script.c
# End Source File
# Begin Source File

SOURCE=.\include\util_script.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\util_win32.c
# End Source File
# Begin Source File

SOURCE=.\server\util_xml.c
# End Source File
# Begin Source File

SOURCE=.\include\util_xml.h
# End Source File
# End Group
# Begin Group "mpm_winnt"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\include\ap_listen.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_mpm.h
# End Source File
# Begin Source File

SOURCE=.\server\listen.c
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm.h
# End Source File
# Begin Source File

SOURCE=.\include\mpm_common.h
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm_default.h
# End Source File
# Begin Source File

SOURCE=.\include\mpm_status.h
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm_winnt.c
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm_winnt.h
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\registry.c
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\service.c
# End Source File
# End Group
# End Target
# End Project
