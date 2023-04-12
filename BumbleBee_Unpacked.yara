rule BumbleBee_Unpacked{
	meta:
		author = "Angelo Violetti (SEC Consult - SEC Defence)"
		date = "2023-02-23"
		description = "Rule to detect BumbleBee in memory"
		reference = "https://sec-consult.com/blog/detail/bumblebee-hunting-with-a-velociraptor/"

	strings:

		/*
			$s1

			mov     rax, [rbx+10h]
			cmp     qword ptr [rbx+18h], 10h
			jb      short loc_18000738F
			mov     rbx, [rbx]
			mov     r8d, eax
			mov     rdx, rbx
			lea     rcx, [rsp+148h+array]
			call    mw_rc4_ksa_wrapper
			nop

			$s2

			mov     r8d, 0FFFh
			lea     rdx, mw_encrypted_config
			lea     rcx, [rsp+148h+array]
			call    mw_rc4_decrypt_wrapper
			nop

			$s3
			lea     rcx, [rsp+148h+array]
			call    mw_return
		*/

		$s1 = {?? 83 ?? 18 10 72 03 ?? 8B ?? 44 8B ?? 48 8B ?? 48 8D 4C 24 30 E8 ?? ?? FF FF 90}

		$s2 = {48 8D 4C 24 30 E8 ?? ?? FF FF 90}

		$s3 = {48 8D 4C 24 30 E8 ?? ?? FF FF}

	condition:
		all of ($s*)
}