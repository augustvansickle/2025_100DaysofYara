rule MAL__PE32_d36ddd249b53b11cad51faf051f8a30c4a618644742cf0b12eae543cb3bc5078 {

	meta:
	author = "august"
	description = "PE32 d36ddd249b53b11cad51faf051f8a30c4a618644742cf0b12eae543cb3bc5078"
	
	strings:
	
		$a1 = "HeapReAlloc"
		$a2 = "GetCommandLineA"
		$a3 = "GetCommandLineW"
		$a4 = "GetModuleHandleW"
		$a5 = "GetStartupInfoW"
		$a6 - "HeapAlloc"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}