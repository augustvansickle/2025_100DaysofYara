rule PE32 {
    meta: 
        description = "100 Days of Yara Rule 22"
    strings:
        $trait_0 = {00 00 00 00 86 08 a9 18 5c 01 be 01 fc 7a 00}
        $trait_1 = {01 b9 01 a7 7a 00 00 00 00}
        $trait_2 = "15015f064d32db0f1db8fa69268d2cc64433e3a673e8b186e362038b9139fd7c"
    condition: 2 of($trait_0, $trait_1, $trait_2)
}