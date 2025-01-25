rule MAL_PE64_QakBotEXE_49220571574da61781de37f35c66e8f0dadb18fdedb6d3a1be67485069cfd4b0 {

meta:
author = "august"
description = "PE64 QakBot EXE 49220571574da61781de37f35c66e8f0dadb18fdedb6d3a1be67485069cfd4b0"

strings:

	$a1 = "BCryptGenRandom" 
	$a2 = "WSASend" 
	$a3 = "WSAIoctl" 
	$a4 = "CryptGenRandom" 
	$a5 = "crypto\\bn\\bn_prime.c" 
	$a6 = "18.244.0.188"
	$h1 = { 61  73  65  5C  62  64  6E  63  2E  70  64  62  00 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}

    