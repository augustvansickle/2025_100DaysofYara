rule MAL_PS1_LOADER_F40F014115CC4F5E51E3819E4B85FF76AE9EE35B02471FC8398664D8AFB2C19A {

meta:
author = "august"
description = "Rule to Detect a PS1 Loader Script F40F014115CC4F5E51E3819E4B85FF76AE9EE35B02471FC8398664D8AFB2C19A"

strings:

	$a1 = "C:\\Users\\Admin\\AppData\\Local\\Temp\\f40f014115cc4f5e51e3819e4b85ff76ae9ee35b02471fc8398664d8afb2c19a.ps1"
	$a2 = "151.49.243.35:443"
	$a3 = "AdjustPrivilegeToken"
	$a4 = "d04e0a6940609bd6f3b561b0f6027f5ca4e8c5cf0fb0d0874b380a0374a8d670"
	$a5 = "47f301ebea6c8bb61069fd63a70c930a9e4d60cf2465e873e9235cd63941d53c" 
	$a6 = "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\590aee7bdd69b59b.customDestinations-ms~RF13523a.TMP" 
	$h1 = { 65 50 72 6f 63 65 73 73 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}