rule MAL__PE64_083773cf97871bc504f12f16a11c3391bea3a7b7427f20958920a089edcc2d77 {

	meta:
	author = "august"
	derscription = "PE64 083773cf97871bc504f12f16a11c3391bea3a7b7427f20958920a089edcc2d77"
	
	strings:
	
		$a1 = "IsWritable"
		$a2 = "&Password"
		$a3 = "&Domain"
		$a4 = "GetClipboardData"
		$a5 = "GetProcAddress"
		$a6 - "CloseHandle"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}