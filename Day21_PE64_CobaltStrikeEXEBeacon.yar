rule MAL_PE64_CobaltStrikeBeaconEXE_fbfb5217a45ca98abda656c49b61fd79bd6cf3bf96e8a1ed4ba0b15fd2024251 {

meta:
author = "august"
description = "PE64 Cobalt Strike Beacon EXE fbfb5217a45ca98abda656c49b61fd79bd6cf3bf96e8a1ed4ba0b15fd2024251"

strings:

	$a1 = "!Beijing Qihu Technology Co., Ltd.0" 
	$a2 = "Caue.EXE" 
	$a3 = "IsDebuggerPresent" 
	$a4 = "_register_thread_local_exe_atexit_callback" 
	$a5 = "KERNEL32:CloseHandle)(HANDLE hObject" 
	$a6 = "i\x00l\x00e\x00I\x00"
	$h1 = { 69 00 70 00 74 00 69 00 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}

    