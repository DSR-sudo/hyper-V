.code
	invalidate_ept_mappings proc
		invept rcx, oword ptr [rdx]

		ret
	invalidate_ept_mappings endp
END