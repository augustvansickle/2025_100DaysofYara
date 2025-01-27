import "pe"
rule MAL_PE32_EXE_d2aa0f3e94249814cc9df7ce269e58036b8385efb86e1549e4636d2cbda29e7d {

	meta:
	author = "august"
	derscription = "PE32 EXE d2aa0f3e94249814cc9df7ce269e58036b8385efb86e1549e4636d2cbda29e7d"
	
	strings:
	
		$a1 = "GetComputerNameW"
		$a2 = "GetNamedPipeInfo"
		$a3 = "    GETMAC /? "
		$a4 = "GetMac.exe"
		$a5 = "VarFileInfo"
		$h1 = { 00 69 00 6E 00 67 00 46 00 }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $h1))
		
	}