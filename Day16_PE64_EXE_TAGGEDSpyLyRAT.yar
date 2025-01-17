import "pe"
rule MAL_PE64_EXE_TaggedSpylyRAT_c781a721f5c27886e0d97d98b572104cfff6eb8d9fd32830fcedf1e3701ceac0 {

meta:
author = "august"
description = "PE64 EXE Tag:SpyLyRAT c781a721f5c27886e0d97d98b572104cfff6eb8d9fd32830fcedf1e3701ceac0"

strings:

	$a1 = "GetSystemInfo" //always good for an operator to see SA
	$a2 = "ResumeThread" //Pausing threads are a good sign of malicious injection 
	$a3 = "VirtualAlloc" //Allocating Memory for stuff and things
	$a4 = "github.com/hhrutter/tiff.encodeGray16"
	$h1 = { 52 62 5a 78 69 6d 65 48 }
	$h2 = { 6f 6d 2f 73 75 6e 73 68 69 }
	$h3 = { 63 6b 42 69 74 73 00 67 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $h1, $h2, $h3))
	
}