rule MAL__PE32_c8624a1e53edcaf70b7d5e4d217ebdf0c41940af11666072b487c6752d7cef42 {

	meta:
	author = "august"
	derscription = "PE32 c8624a1e53edcaf70b7d5e4d217ebdf0c41940af11666072b487c6752d7cef42"
	
	strings:
	
		$a1 = "System.Runtime.CompilerServices"
		$a2 = "DebuggerDisplayAttribute"
		$a3 = "AsyncCallback"
		$a4 = "DebuggerHiddenAttribute"
		$a5 = "GetFolderPath"
		$a6 - "System.Net.Sockets"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}