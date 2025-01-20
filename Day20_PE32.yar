rule MAL_PE32_8e43addcb5c8326a8811982336b8fa65fd2b00a7141c8cf267114f2fb356d98f {

meta:
author = "august"
description = "PE32 8e43addcb5c8326a8811982336b8fa65fd2b00a7141c8cf267114f2fb356d98f"

strings:

	$a1 = "GetModuleHandleA" 
	$a2 = "PeekNamedPipe" 
	$a3 = "_LibMain@12" 
	$a4 = "GetCurrentThreadId" 
	$a5 = "IsWindowVisible" 
	$a6 = { 5C 81 26 8E B2 50 42 01 B7 }
	$h1 = { 3C 50 E1 31 67 12 42 8A E2 }
 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}

    