# Microsoft Developer Studio Project File - Name="ApacheModuleAuthDigest" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=ApacheModuleAuthDigest - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleAuthDigest.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleAuthDigest.mak" CFG="ApacheModuleAuthDigest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleAuthDigest - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleAuthDigest - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheModuleAuthDigest - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ".\ApacheModuleAuthDigestR"
# PROP BASE Intermediate_Dir ".\ApacheModuleAuthDigestR"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".\ApacheModuleAuthDigestR"
# PROP Intermediate_Dir ".\ApacheModuleAuthDigestR"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\..\include" /I ".\\" /I "..\..\lib\apr\include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ApacheCore.lib aprlib.lib kernel32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 ApacheCore.lib aprlib.lib kernel32.lib /nologo /subsystem:windows /dll /map /machine:I386 /libpath:"..\..\CoreR" /libpath:"..\..\lib\apr\Release" /base:@BaseAddr.ref,mod_auth_digest
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "ApacheModuleAuthDigest - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ".\ApacheModuleAuthDigestD"
# PROP BASE Intermediate_Dir ".\ApacheModuleAuthDigestD"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\ApacheModuleAuthDigestD"
# PROP Intermediate_Dir ".\ApacheModuleAuthDigestD"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "..\..\include" /I ".\\" /I "..\..\lib\apr\include" /D "_DEBUG" /D "SHARED_MODULE" /D "WIN32" /D "_WINDOWS" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ApacheCore.lib aprlib.lib kernel32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ApacheCore.lib aprlib.lib kernel32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"..\..\CoreD" /libpath:"..\..\lib\apr\Debug" /base:@BaseAddr.ref,mod_auth_digest
# SUBTRACT LINK32 /pdb:none /incremental:no /map

!ENDIF 

# Begin Target

# Name "ApacheModuleAuthDigest - Win32 Release"
# Name "ApacheModuleAuthDigest - Win32 Debug"
# Begin Source File

SOURCE=..\..\modules\standard\mod_auth_digest.c
# End Source File
# End Target
# End Project
