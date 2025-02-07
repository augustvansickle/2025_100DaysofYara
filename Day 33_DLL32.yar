rule MAL__PE32_DLL_8a074fb89bd8b6d7ad336623f2becd465c2eced596590f3fdb767189426675d8 {

	meta:
	author = "august"
	derscription = "PE32 DLL 8a074fb89bd8b6d7ad336623f2becd465c2eced596590f3fdb767189426675d8"
	
	strings:
	
		$a1 = "__dllonexit"
		$a2 = "SetClipboardData"
		$a3 = "CreateFileMappingW"
		$a4 = "gethostname"
		$a5 = "QLoadLibraryA"
		$a6 - "&ResumeThread"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}