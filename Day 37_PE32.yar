rule MAL__PE32_814daa8a83b49db3698436bb3ea741cb49f5b78bd0ffd439c3a6ead606c339f0 {

	meta:
	author = "august"
	derscription = "PE32 814daa8a83b49db3698436bb3ea741cb49f5b78bd0ffd439c3a6ead606c339f0"
	
	strings:
	
		$a1 = "CreateLocalNamedPipe "
		$a2 = "WaitNamedPipe"
		$a3 = "DisconnectNamedPipe"
		$a4 = "TokenElevationType"
		$a5 = "LoadedImageBase"
		$a6 - "Impersonate"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}