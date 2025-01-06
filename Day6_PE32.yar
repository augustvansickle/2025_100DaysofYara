rule MAL_PE32_31ebf7219722b8c908a914b2b08c5d03140af8b0cef6c96152e458dc82301c0a {

meta:
author = "august"
description = "PE32 31ebf7219722b8c908a914b2b08c5d03140af8b0cef6c96152e458dc82301c0a"

strings:

	$a1 = "TryAcquireSRWLockExclusive" //unique call
	$a2 = "IsDebuggerPresent" 
	$a3 = "IsProcessorFeaturePresent"
	$a4 = "SetUnhandledExceptionFilter"
	$a5 = "TlsAlloc"
	$a6 = "extern HANDLE __stdcall FindFirstFileExW"
	$h1 = { E8 55 02 00 00 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}