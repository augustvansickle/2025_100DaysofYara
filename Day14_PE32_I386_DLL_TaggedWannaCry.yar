import "pe"
rule MAL_I386_PE32_DLL_WANNACRY_e55ff68c216152b45e9e2a900cc584907c16bfcfdeb5ed6cc83ec227af907661 {

meta:
author = "august"
description = "PE32 I386 DLL Tag:WannaCry e55ff68c216152b45e9e2a900cc584907c16bfcfdeb5ed6cc83ec227af907661"

strings:

	$a1 = "launcher.dll" 
	$a2 = "\x00d\x00e\x00f\x00a\x00u\x00l\x00t\x00_\x00i\x00n\x00j\x00e\x00c\x00t\x00i\x00o\x00n\x00" 
	$a3 = "CreateProcessA"
	$a4 = "var pc = runtime.GetPropertiesContainer();"
	$h1 = { 72 00 75 00 6e 00 74 00 69 00 6d 00 65 00 2e 00 }
	$h2 = { 47 00 65 00 74 00 41 00 75 00 74 00 68 00 50 00 }
	$h3 = { 6f 00 6c 00 69 00 63 00 79 00 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $h1, $h2, $h3))
	
}