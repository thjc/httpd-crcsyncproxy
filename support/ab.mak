# Microsoft Developer Studio Generated NMAKE File, Based on ab.dsp
!IF "$(CFG)" == ""
CFG=ab - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ab - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ab - Win32 Release" && "$(CFG)" != "ab - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ab.mak" CFG="ab - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ab - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "ab - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ab - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ab.exe"

!ELSE 

ALL : "aprutil - Win32 Release" "httpd - Win32 Release" "apr - Win32 Release"\
 "$(OUTDIR)\ab.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 ReleaseCLEAN" "httpd - Win32 ReleaseCLEAN"\
 "aprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ab.idb"
	-@erase "$(INTDIR)\ab.obj"
	-@erase "$(OUTDIR)\ab.exe"
	-@erase "$(OUTDIR)\ab.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "../srclib/apr/include" /I\
 "../srclib/apr-util/include" /I "../include" /I "../os/win32" /D "NDEBUG" /D\
 "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "AP_DECLARE_STATIC"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ab" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ab.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo\
 /subsystem:console /incremental:no /pdb:"$(OUTDIR)\ab.pdb"\
 /map:"$(INTDIR)\ab.map" /machine:I386 /out:"$(OUTDIR)\ab.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ab.obj" \
	"..\LibR\httpd.lib" \
	"..\srclib\apr-util\LibR\aprutil.lib" \
	"..\srclib\apr\LibR\apr.lib"

"$(OUTDIR)\ab.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ab - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ab.exe"

!ELSE 

ALL : "aprutil - Win32 Debug" "httpd - Win32 Debug" "apr - Win32 Debug"\
 "$(OUTDIR)\ab.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 DebugCLEAN" "httpd - Win32 DebugCLEAN"\
 "aprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ab.idb"
	-@erase "$(INTDIR)\ab.obj"
	-@erase "$(OUTDIR)\ab.exe"
	-@erase "$(OUTDIR)\ab.ilk"
	-@erase "$(OUTDIR)\ab.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../srclib/apr/include" /I\
 "../srclib/apr-util/include" /I "../include" /I "../os/win32" /D "_DEBUG" /D\
 "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "AP_DECLARE_STATIC"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ab" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ab.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo\
 /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\ab.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)\ab.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\ab.obj" \
	"..\LibD\httpd.lib" \
	"..\srclib\apr-util\LibD\aprutil.lib" \
	"..\srclib\apr\LibD\apr.lib"

"$(OUTDIR)\ab.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ab - Win32 Release" || "$(CFG)" == "ab - Win32 Debug"

!IF  "$(CFG)" == "ab - Win32 Release"

"apr - Win32 Release" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" 
   cd "..\..\support"

"apr - Win32 ReleaseCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\apr.mak" CFG="apr - Win32 Release"\
 RECURSE=1 
   cd "..\..\support"

!ELSEIF  "$(CFG)" == "ab - Win32 Debug"

"apr - Win32 Debug" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" 
   cd "..\..\support"

"apr - Win32 DebugCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\apr.mak" CFG="apr - Win32 Debug" RECURSE=1\
 
   cd "..\..\support"

!ENDIF 

!IF  "$(CFG)" == "ab - Win32 Release"

"httpd - Win32 Release" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\httpd.mak" CFG="httpd - Win32 Release" 
   cd ".\support"

"httpd - Win32 ReleaseCLEAN" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\httpd.mak" CFG="httpd - Win32 Release"\
 RECURSE=1 
   cd ".\support"

!ELSEIF  "$(CFG)" == "ab - Win32 Debug"

"httpd - Win32 Debug" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\httpd.mak" CFG="httpd - Win32 Debug" 
   cd ".\support"

"httpd - Win32 DebugCLEAN" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\httpd.mak" CFG="httpd - Win32 Debug"\
 RECURSE=1 
   cd ".\support"

!ENDIF 

!IF  "$(CFG)" == "ab - Win32 Release"

"aprutil - Win32 Release" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" 
   cd "..\..\support"

"aprutil - Win32 ReleaseCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\aprutil.mak" CFG="aprutil - Win32 Release"\
 RECURSE=1 
   cd "..\..\support"

!ELSEIF  "$(CFG)" == "ab - Win32 Debug"

"aprutil - Win32 Debug" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" 
   cd "..\..\support"

"aprutil - Win32 DebugCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\aprutil.mak" CFG="aprutil - Win32 Debug"\
 RECURSE=1 
   cd "..\..\support"

!ENDIF 

SOURCE=.\ab.c
DEP_CPP_AB_C0=\
	"..\include\ap_config.h"\
	"..\include\ap_mmn.h"\
	"..\os\win32\os.h"\
	"..\srclib\apr-util\include\ap_base64.h"\
	"..\srclib\apr-util\include\ap_hooks.h"\
	"..\srclib\apr\include\apr.h"\
	"..\srclib\apr\include\apr_errno.h"\
	"..\srclib\apr\include\apr_file_io.h"\
	"..\srclib\apr\include\apr_general.h"\
	"..\srclib\apr\include\apr_getopt.h"\
	"..\srclib\apr\include\apr_lib.h"\
	"..\srclib\apr\include\apr_network_io.h"\
	"..\srclib\apr\include\apr_pools.h"\
	"..\srclib\apr\include\apr_strings.h"\
	"..\srclib\apr\include\apr_tables.h"\
	"..\srclib\apr\include\apr_time.h"\
	"..\srclib\apr\include\apr_xlate.h"\
	"..\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_AB_C0=\
	"..\include\ap_config_auto.h"\
	"..\include\ap_config_path.h"\
	

"$(INTDIR)\ab.obj" : $(SOURCE) $(DEP_CPP_AB_C0) "$(INTDIR)"



!ENDIF 

