rule MAL__PE64_875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24 {

	meta:
	author = "august"
	derscription = "PE64 875b0cbad25e04a255b13f86ba361b58453b6f3c5cc11aca2db573c656e64e24"
	
	strings:
	
		$a1 = "endstream "
		$a2 = "HeapReAlloc"
		$a3 = "GetEnvironmentStringsW"
		$a4 = "WriteFile"
		$a5 = "IsDebuggerPresent"
		$a6 - "GetCurrentThreadId"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}