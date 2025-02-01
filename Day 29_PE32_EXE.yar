rule MAL__PE32_JuOCtrZUP_EXE_fc812bd47c01bbc0c2cea592d867a671589c336f7c064948068ee5bdba647faa {

	meta:
	author = "august"
	derscription = "PE32 EXE .NET JuOCtrZUP fc812bd47c01bbc0c2cea592d867a671589c336f7c064948068ee5bdba647faa"
	
	strings:
	
		$a1 = "WebClient"
		$a2 = "CreateProcess"
		$a3 = "DebuggingModes"
		$a4 = "Silent Updates"
		$a5 = "Sleep"
		$a6 - "JuOCtrZUP.exe"
		$h1 = { 61 69 6e 00 6d 73 63 6f }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6, $h1))
		
	}