import re
import struct

def parse_header_file(path):
    with open(path, 'r') as f:
        content = f.read()
    
    # Extract rwbase_image array
    match = re.search(r'const unsigned char rwbase_image\[\] = \{(.*?)\};', content, re.DOTALL)
    if not match:
        print("Could not find rwbase_image")
        return

    hex_data = match.group(1).replace('\n', '').replace(' ', '').split(',')
    # Filter empty strings
    hex_data = [x for x in hex_data if x]
    bytes_data = bytearray([int(x, 16) for x in hex_data])
    
    print(f"Total Bytes Read: {len(bytes_data)}")
    
    # Parse DOS Header
    e_magic = struct.unpack_from('<H', bytes_data, 0)[0]
    if e_magic != 0x5A4D:
        print("Invalid DOS Signature")
        return
        
    e_lfanew = struct.unpack_from('<I', bytes_data, 0x3C)[0]
    print(f"e_lfanew: 0x{e_lfanew:X}")
    
    # Parse NT Header
    signature = struct.unpack_from('<I', bytes_data, e_lfanew)[0]
    if signature != 0x4550: # PE\0\0
        print("Invalid NT Signature")
        return
        
    # File Header
    file_header_offset = e_lfanew + 4
    num_sections = struct.unpack_from('<H', bytes_data, file_header_offset + 2)[0]
    size_of_optional_header = struct.unpack_from('<H', bytes_data, file_header_offset + 16)[0]
    
    print(f"Number of Sections: {num_sections}")
    
    # Optional Header
    opt_header_offset = file_header_offset + 20
    magic = struct.unpack_from('<H', bytes_data, opt_header_offset)[0]
    
    if magic == 0x20B: # PE32+
        print("Format: PE32+ (64-bit)")
        size_of_code = struct.unpack_from('<I', bytes_data, opt_header_offset + 4)[0]
        size_of_init_data = struct.unpack_from('<I', bytes_data, opt_header_offset + 8)[0]
        size_of_uninit_data = struct.unpack_from('<I', bytes_data, opt_header_offset + 12)[0]
        address_of_entry = struct.unpack_from('<I', bytes_data, opt_header_offset + 16)[0]
        base_of_code = struct.unpack_from('<I', bytes_data, opt_header_offset + 20)[0]
        
        # Windows Specific Fields
        image_base = struct.unpack_from('<Q', bytes_data, opt_header_offset + 24)[0]
        section_alignment = struct.unpack_from('<I', bytes_data, opt_header_offset + 32)[0]
        file_alignment = struct.unpack_from('<I', bytes_data, opt_header_offset + 36)[0]
        size_of_image = struct.unpack_from('<I', bytes_data, opt_header_offset + 56)[0]
        size_of_headers = struct.unpack_from('<I', bytes_data, opt_header_offset + 60)[0]
        
        print(f"SizeOfCode: 0x{size_of_code:X}")
        print(f"SizeOfInitializedData: 0x{size_of_init_data:X}")
        print(f"SizeOfUninitializedData: 0x{size_of_uninit_data:X}")
        print(f"AddressOfEntryPoint: 0x{address_of_entry:X}")
        print(f"SectionAlignment: 0x{section_alignment:X}")
        print(f"FileAlignment: 0x{file_alignment:X}")
        print(f"SizeOfImage: 0x{size_of_image:X}")
        print(f"SizeOfHeaders: 0x{size_of_headers:X}")
        
        # Parse Sections
        section_table_offset = opt_header_offset + size_of_optional_header
        print("\nSections:")
        print(f"{'Name':<8} {'VirtAddr':<10} {'VirtSize':<10} {'RawAddr':<10} {'RawSize':<10}")
        for i in range(num_sections):
            offset = section_table_offset + (i * 40)
            name = bytes_data[offset:offset+8].rstrip(b'\x00').decode('utf-8', errors='ignore')
            v_size = struct.unpack_from('<I', bytes_data, offset + 8)[0]
            v_addr = struct.unpack_from('<I', bytes_data, offset + 12)[0]
            raw_size = struct.unpack_from('<I', bytes_data, offset + 16)[0]
            raw_addr = struct.unpack_from('<I', bytes_data, offset + 20)[0]
            print(f"{name:<8} 0x{v_addr:<9X} 0x{v_size:<9X} 0x{raw_addr:<9X} 0x{raw_size:<9X}")

parse_header_file(r'c:\Users\DRS\source\repos\DSR-sudo\hyper-V\shared\payload\payload_bin.h')
