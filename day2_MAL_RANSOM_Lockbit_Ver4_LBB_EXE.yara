import "pe"

rule MAL_RANSOM_Lockbit_Ver4_LBB_EXE {

meta:
author = "august"
description = "Rule to detect Lockbit4 PE"

strings:

	$a1 = "CreateDialogParamW"
	$a2 = "const GetCommandLineA)() = ::GetCommandLineA;"
	$a3 = "KERNEL32:GetCommandLineA)() = GetCommandLineA"
	$h1 = { 74 43 6f 6d 4e 61 6d }

condition:

	any of them
	
}