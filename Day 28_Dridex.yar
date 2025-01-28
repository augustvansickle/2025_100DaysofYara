rule MAL__PE32_Dridex_DLL_0e0d4494780c9010ece88f39f65bfbfcb13236e1652f7fe41e9c84a5b16583a5 {

	meta:
	author = "august"
	derscription = "PE32 DLL DRIDEX 0e0d4494780c9010ece88f39f65bfbfcb13236e1652f7fe41e9c84a5b16583a5"
	
	strings:
	
		$a1 = "EnableExecuteProtectionSupportW"
		$a2 = " Cleaner"
		$a3 = "System Cleaning"
		$a4 = "Silent Updates"
		$a5 = "RmnPjJkd.pdb"
		$h1 = { 00 67 00 61 00 6c 00 00 }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $h1))
		
	}