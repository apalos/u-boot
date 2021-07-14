.section .rodata.capsule_key.init,"a"
.balign 16
.global __efi_capsule_sig_begin
__efi_capsule_sig_begin:
.incbin CONFIG_EFI_CAPSULE_KEY_PATH
__efi_capsule_sig_end:
.global __efi_capsule_sig_end
.balign 16
