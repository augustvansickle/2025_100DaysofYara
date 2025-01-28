rule MAL_NET_LOKI_da32c24a460cc7a3134f189037333434ae1160aa97121b85a938060d1dbd1be8 {

	meta:
	author = "august"
	derscription = "NET VBA da32c24a460cc7a3134f189037333434ae1160aa97121b85a938060d1dbd1be8"
	
	strings:
	
		$a1 = "get_Computer"
		$a2 = "_CorExeMain"
		$a3 = "Discord Link :  v1.0.0-custom"
		$a4 = "NtResumeThread"
		$a5 = "VirtualAllocEx"
		$h1 = { 51 73 52 45 5a 2f 78 47 4e }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $h1))
		
	}