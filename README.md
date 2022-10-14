# Process-Hollowing
My implementation of the process hollowing technique (aka RunPE or Dynamic Forking)

*for educational purposes only*

My implementation supports:
- PE32 images with the same subsytem
- Relocations for images with different image base address

### How To Use
ProcessHollowing.exe expects to get the images paths via command-line arguments in this order:

`ProcessHollowing.exe [host_path] [payload_path]`
