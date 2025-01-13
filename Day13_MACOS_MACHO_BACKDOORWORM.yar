rule MAL_MACOS_MACHO_BACKDOOR_WORM_9812152828862aa4b906049e83017fa02dea27e76b2543a7121ac259cafea722 {

meta:
author = "august"
description = "Rule for MacOS MACHO Backdoor-Worm 211xahcou.dll 9812152828862aa4b906049e83017fa02dea27e76b2543a7121ac259cafea722"

strings:

	$a1 = "//usr//lib//libgcc_s.1.dylib\x00\x00" //dylib
	$a2 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" 
	$a3 = "_AuthorizationExecuteWithPrivileges" 
	$a4 = "_CFBundleCopyExecutableURL" //private function that pulls a URL from the exe
	$a5 = "/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon"
	$h1 = { 46 72 61 6d 65 77 6f 72 6b 73 2f 43 61 72 62 6f }
	$h2 = { 2f 53 79 73 74 65 6d }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $h1, $h2))
	
}