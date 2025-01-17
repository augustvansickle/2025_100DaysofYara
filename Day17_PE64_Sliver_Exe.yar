import "pe"
rule MAL_PE64_EXE_Sliver_03d0b177ff78511a22ca0478436e9eb7b57b009f0bf986301284b30068fa38de {

meta:
author = "august"
description = "PE64 EXE Sliver 03d0b177ff78511a22ca0478436e9eb7b57b009f0bf986301284b30068fa38de"

strings:

	$a1 = "Sleep" //Time based Beacon Evasion
	$a2 = "a.out.exe" //
	$a3 = "Built by MinGW-W64 project" // Compiler info, Sliver uses MinGW to compile beacons
	$a4 = "net/sockaddr_posix.go"
	$h1 = { 6f 6d 70 72 65 73 73 2f }
	$h2 = { 73 73 6f 72 29 2e 68 75 66 }
	$h3 = { 64 65 72 00 62 75 66 69 6f }

condition:

	(2 of ($a1, $a2, $a3, $a4, $h1, $h2, $h3))
	
}