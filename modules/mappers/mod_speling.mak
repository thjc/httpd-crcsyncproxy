# Microsoft Developer Studio Generated NMAKE File, Based on mod_speling.dsp
!IF "$(CFG)" == ""
CFG=mod_speling - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_speling - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_speling - Win32 Release" && "$(CFG)" !=\
 "mod_speling - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_speling.mak" CFG="mod_speling - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_speling - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_speling - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_speling - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_speling.so"

!ELSE 

ALL : "libaprutil - Win32 Release" "libhttpd - Win32 Release"\
 "libapr - Win32 Release" "$(OUTDIR)\mod_speling.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN"\
 "libaprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_speling.idb"
	-@erase "$(INTDIR)\mod_speling.obj"
	-@erase "$(OUTDIR)\mod_speling.exp"
	-@erase "$(OUTDIR)\mod_speling.lib"
	-@erase "$(OUTDIR)\mod_speling.map"
	-@erase "$(OUTDIR)\mod_speling.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\srclib\apr\include" /I "../../srclib/apr-util/include" /D "NDEBUG" /D\
 "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_speling" /FD /c 
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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_speling.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\mod_speling.pdb" /map:"$(INTDIR)\mod_speling.map" /machine:I386\
 /out:"$(OUTDIR)\mod_speling.so" /implib:"$(OUTDIR)\mod_speling.lib"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_speling 
LINK32_OBJS= \
	"$(INTDIR)\mod_speling.obj" \
	"..\..\Release\libhttpd.lib" \
	"..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\mod_speling.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_speling - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_speling.so"

!ELSE 

ALL : "libaprutil - Win32 Debug" "libhttpd - Win32 Debug"\
 "libapr - Win32 Debug" "$(OUTDIR)\mod_speling.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN"\
 "libaprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_speling.idb"
	-@erase "$(INTDIR)\mod_speling.obj"
	-@erase "$(OUTDIR)\mod_speling.exp"
	-@erase "$(OUTDIR)\mod_speling.lib"
	-@erase "$(OUTDIR)\mod_speling.map"
	-@erase "$(OUTDIR)\mod_speling.pdb"
	-@erase "$(OUTDIR)\mod_speling.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\srclib\apr\include" /I "../../srclib/apr-util/include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_speling" /FD /c 
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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_speling.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\mod_speling.pdb" /map:"$(INTDIR)\mod_speling.map" /debug\
 /machine:I386 /out:"$(OUTDIR)\mod_speling.so"\
 /implib:"$(OUTDIR)\mod_speling.lib"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_speling 
LINK32_OBJS= \
	"$(INTDIR)\mod_speling.obj" \
	"..\..\Debug\libhttpd.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\mod_speling.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "mod_speling - Win32 Release" || "$(CFG)" ==\
 "mod_speling - Win32 Debug"

!IF  "$(CFG)" == "mod_speling - Win32 Release"

"libapr - Win32 Release" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\mappers"

"libapr - Win32 ReleaseCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\mappers"

!ELSEIF  "$(CFG)" == "mod_speling - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\mappers"

"libapr - Win32 DebugCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\mappers"

!ENDIF 

!IF  "$(CFG)" == "mod_speling - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\mappers"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\mappers"

!ELSEIF  "$(CFG)" == "mod_speling - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\mappers"

"libhttpd - Win32 DebugCLEAN" : 
   cd "\test\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd ".\modules\mappers"

!ENDIF 

!IF  "$(CFG)" == "mod_speling - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\..\modules\mappers"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\..\modules\mappers"

!ELSEIF  "$(CFG)" == "mod_speling - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\mappers"

"libaprutil - Win32 DebugCLEAN" : 
   cd "\test\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\..\modules\mappers"

!ENDIF 

SOURCE=.\mod_speling.c
DEP_CPP_MOD_S=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_uri.h"\
	"..\..\os\win32\os.h"\
	"..\..\srclib\apr-util\include\ap_buckets.h"\
	"..\..\srclib\apr-util\include\ap_hooks.h"\
	"..\..\srclib\apr-util\include\ap_ring.h"\
	"..\..\srclib\apr\include\apr.h"\
	"..\..\srclib\apr\include\apr_errno.h"\
	"..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
	"..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\srclib\apr\include\apr_pools.h"\
	"..\..\srclib\apr\include\apr_strings.h"\
	"..\..\srclib\apr\include\apr_tables.h"\
	"..\..\srclib\apr\include\apr_thread_proc.h"\
	"..\..\srclib\apr\include\apr_time.h"\
	"..\..\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_S=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\ap_config_path.h"\
	

"$(INTDIR)\mod_speling.obj" : $(SOURCE) $(DEP_CPP_MOD_S) "$(INTDIR)"



!ENDIF 

