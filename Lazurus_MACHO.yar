rule MAL_LAZARUS_MACHO_176e8a5a7b6737f8d3464c18a77deef778ec2b9b42b7e7eafc888aeaf2758c2d {

meta:
author = "august"
description = "MacOS Macho Lazarus Binary 176e8a5a7b6737f8d3464c18a77deef778ec2b9b42b7e7eafc888aeaf2758c2d"

strings:

	$a1 = "int32_t (* const _setgroups)(int32_t, gid_t*) = _setgroups"
	$a2 = "OSStatus _InstallEventHandler"
	$a3 = "1009cb8b0  extern int32_t _mkdir(char const*, mode_t)"
	$a4 = "_$LT$$LP$$RF$str$C$u16$RP$$u20$as$u20$std..net..socket_addr..ToSocketAddrs$GT$::to_socket_addrs::h93d5f2ed04ddac6f"
	$a5 = "/usr/lib/libobjc.A.dylib"
	$h1 = { 74 2e 66 72 61 6d 65 77 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $h1))
	
}