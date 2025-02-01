rule MAL__PE32_EXE_aea61181503fbd6e864c4675de0be477fb1d514505c7b40a536229fa70177bf0 {

	meta:
	author = "august"
	derscription = "PE32 EXE  aea61181503fbd6e864c4675de0be477fb1d514505c7b40a536229fa70177bf0"
	
	strings:
	
		$a1 = "TCPTimeout"
		$a2 = "Software\\AutoIt v3\\AutoIt"
		$a3 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h"
		$a4 = ".?AVtype_info@@"
		$a5 = "ResumeThread"
		$a6 = "IsProcessorFeaturePresent"
		$h1 = { 68 20 61 20 6e 6f 6e 2d 64 }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6, $h1))
		
	}
