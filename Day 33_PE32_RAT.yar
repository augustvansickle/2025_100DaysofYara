rule MAL__PE32_RAT_aab512030974507c73bfa580ea67ffba4629ea44ab61c60ae0b85560c97e1867 {

	meta:
	author = "august"
	derscription = "PE32 RAT aab512030974507c73bfa580ea67ffba4629ea44ab61c60ae0b85560c97e1867"
	
	strings:
	
		$a1 = "Dispose__Instance__"
		$a2 = "Create__Instance__"
		$a3 = "get_Buffer"
		$a4 = "get_Hash"
		$a5 = "WriteLine"
		$a6 - "get_MachineName"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}