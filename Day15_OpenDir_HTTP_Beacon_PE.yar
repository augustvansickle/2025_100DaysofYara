import "pe"
rule MAL_PE32_EXE_HTTP_BEACON_0e5a70939990cae6e257c9ac03e7a476709489927b7eddf11ad0592433f90724 {

meta:
author = "august"
description = "PE32 HTTP Beacon 0e5a70939990cae6e257c9ac03e7a476709489927b7eddf11ad0592433f90724"

strings:

	$a1 = "GetEnvironmentStringsW" 
	$a2 = "GetCurrentProcess" 
	$a3 = " KERNEL32:Sleep)(uint32_t dwMilliseconds" 
	$a4 = "BOOL (__stdcall* const KERNEL32:PeekNamedPipe)" 
	$a5 = " __stdcall GetProcAddress" 
	$a6 = "89.197.154.116" //
	$h1 = { 38 39 2e 31 39 37 2e 31 35 34 2e 31 31 36 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}

    