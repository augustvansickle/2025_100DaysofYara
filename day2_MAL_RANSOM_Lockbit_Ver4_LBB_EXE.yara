import "pe"

rule MAL_RANSOM_Lockbit_Ver4_LBB_EXE {

meta:
author = "august"
description = "Rule to detect Lockbit4 PE"

strings:

	$a1 = "CreateDialogParamW" fullword ascii
	$a2 = "GetCommandLineA" fullword ascii
	$a3 = "int32_t __stdcall DialogBoxParamW" 
	$a4 = "uint32_t __stdcall GetFileAttributesW(PWSTR lpFileName)" 
	$h1 = { 74 43 6f 6d 4e 61 6d }
	$h2 = { 00 42 c1 50 }

condition:

	($a1 and $a2 and $a3) and any of ($h1, $h2)
	
}
