import "pe"
rule MAL_PE64_DLL_LEGIONLOADER_23f064df01ee9eedf9e1341185505b86148873ccc0a922c64bb085ceb5b091fc {

meta:
author = "august"
description = "PE64 DLL Legion Loader 23f064df01ee9eedf9e1341185505b86148873ccc0a922c64bb085ceb5b091fc"

strings:

	$a1 = "GetModuleHandleExW" 
	$a2 = "RegCreateKeyExW" 
	$a3 = "GetDC" 
	$a4 = " VirtualProtectEx" 
	$a5 = "TerminateThread" 
	$a6 = { 74 45 6e 76 69 72 6f 6e }
	$h1 = { 74 64 48 61 6e 64 6c 65 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}

    