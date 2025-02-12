rule MAL__PE32_b758560d291f4483bf7071fa3ff4017e1f421681a264cd8df1d72440a7020ce8 {

	meta:
	author = "august"
	description = "PE32 b758560d291f4483bf7071fa3ff4017e1f421681a264cd8df1d72440a7020ce8"
	
	strings:
	
		$a1 = "CreateInstance"
		$a2 = "Clone"
		$a3 = "DebuggerBrowsableState"
		$a4 = "DebuggableAttribute"
		$a5 = "DebuggingModes"
		$a6 - "http://tempuri.org/airlineDataSet1.xsd"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}