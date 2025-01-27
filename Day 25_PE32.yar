import "pe"
rule MAL_PE32_EXE_bba4cd97ea9a1dbe8b1bb1dc19474a22c4f3427ff8ae695f64e93af58ce16eaa {

	meta:
	author = "august"
	derscription = "PE32 EXE bba4cd97ea9a1dbe8b1bb1dc19474a22c4f3427ff8ae695f64e93af58ce16eaa"
	
	strings:
	
		$a1 = "DeleteUrlCacheEntry"
		$a2 = "FindFirstUrlCacheEntryA"
		$a3 = "RegOpenKeyExA"
		$a4 = "_sleep"
		$a5 = "GetProcAddress"
		$h1 = { 6F 43 72 65 61 74 65 49 6E }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $h1))
		
	}