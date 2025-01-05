rule MAL_ELF_bdcbe3391365cdff66b9084280eb9884df48bebf38295d2f4bd7273666d04fed {

meta:
author = "august"
description = "ELF Binary bdcbe3391365cdff66b9084280eb9884df48bebf38295d2f4bd7273666d04fed"

strings:

	$a1 = "\xf2\x8f\x09\x00\xab\xab\xab\xab\xeb\x57" //shellcode
	$a2 = "(syscall(0x12a" //nonstandard syscall
	$a3 = "semtex.c"
	$a4 = "_Jv_RegisterClasses"
	$h1 = { 2f 62 69 6e 2f 62 61 73 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $h1))
	
}
