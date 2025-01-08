import "dll"

rule MAL_RANSOM_DLL_HIVE {

meta:
author = "august"
description = "Rule for HiveRansomware DLL 211xahcou.dll 33ACEB3DC0681A56226D4CFCE32EEE7A431E66F5C746A4D6DC7506A72B317277"

strings:

	$a1 = "extrn GetSystemInfo:qword" fullword ascii
	$a2 = "extrn Sleep:qword" fullword ascii
	$a3 = "SetWaitableTimer)(HANDLE hTimer, const LARGE_INTEGER *lpDueTime, LONG lPeriod," 
	$a4 = "; BOOL (__stdcall *DuplicateHandle)" 
	$a5 = "kernel32:SuspendThread)(HANDLE hThread) = SuspendThread"
	$h1 = { 6e 45 6c 74 01 12 2a 74 }
	$h2 = { 65 66 6c 65 63 74 2e 6d }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $h1, $h2))
	
}