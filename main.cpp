/*
 elfcrypter
 
 Copyright (c) 2012 Johannes 'blub.txt' Schröter. All rights reserved.
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "funcs.h"

unsigned long dwStartEncrypt = NULL;
unsigned long EncryptSize    = NULL;
unsigned long dwOldEntry     = NULL;

void PRE_LOADER()
{
    asm(
    "pushad\n"
    "call GetEIP\n"

    "GetEIP:\n"
    "pop edx\n"
    "add edx, 89\n"
    
    "mov     esi, [edx]\n"

    "mov ebx, [edx]\n"
    "and ebx, 0xFFFFF000\n"

    "mov eax, 125\n"
    "mov ecx, 0x1000\n"
    "mov edx, 0x7\n"
    "int 0x80\n"

    "call GetEIP2\n"

    "GetEIP2:\n"
    "pop edx\n"

    "add edx, 57\n"
    "mov     edi, [edx]\n"

    "mov     edx, 0x57\n"
    "mov     eax, 0\n"
    "lea     esi, [esi+0]\n"

    "CryptLoop:\n"
    "mov     ecx, edx\n"
    "xor     cl, [eax+esi]\n"
    "mov     [eax+esi], cl\n"
    "add     eax, 1\n"
    "cmp     eax, edi\n"
    "lea     edx, [ecx+edx+0x57]\n"
    "jnz     short CryptLoop\n"

    "popad\n"

    "call GetEIP3\n"

    "GetEIP3:\n"
    "pop ebp\n"

    "add ebp, 10\n"
    "mov edx, [ebp]\n"
    "jmp [ebp]\n"

    "_ORG_ENTRY_POINT:\n"
    "INT3\n"
    "INT3\n"
    "INT3\n"
    "INT3\n"

    "_OLD_CODE_SIZE:\n"
    "INT3\n"
    "INT3\n"
    "INT3\n"
    "INT3\n"
    );
}
void PRE_LOADER_END(void) { }

int main( int argc, char* argv[] )
{
    int fd = 0;
    struct stat st;

    bool bNoteFound = false;
    bool bTextFound = false;

    Elf32_Ehdr ehdr;
    Elf32_Shdr shdr;
    Elf32_Phdr phdr;
    Elf32_Shdr * StringTable;

    unsigned long dwAddress;
    unsigned long dwBaseAddress;
    unsigned long dwNewEntry;
    unsigned long dwSectionSize;
    unsigned long dwSectionOffset;

    size_t iLoaderSize;

    char szBackName[256];
    char * szSectionName;

    printf( "\n%s by blub.txt\n", argv[0] );
    printf( "Usage: %s <ELF Executable> [ Options ]\n\n", argv[0] );

    if ( argc != 2 )
    {
        printf( "usage: %s filename", argv[0] );
    }

    if( !file_exists( argv[1] ) )
    {
        printf( "* Error: %s not found!\n", argv[1] );
        return -1;
    }

    printf( "- Creating a backup of %s\n", argv[1] );

    strcpy( szBackName, argv[1] );
    strcat( szBackName, ".backup" );

    if( iBackup( szBackName, argv[1] ) != NULL )
    {
        printf( "* Error: Creating Backup\n" );
        return 1;
    }

    if( file_exists( szBackName ) )
    printf( "  Backup of %s created!\n  Renamed to %s\n", argv[1], szBackName );

    printf( "- Reading ELF header of %s\n", argv[1] );

    if( (fd = open( argv[1], O_RDWR ) ) == -1 )
	{
		printf( "* Error: open\n" );
		return -1;
	}

	if( fstat( fd, &st ) < 0 )
	{
	    printf( "* Error: fstat\n" );
	    return -1;
	}

	iLoaderSize = ( size_t )( PRE_LOADER_END ) - (size_t)( PRE_LOADER );

	dwAddress = mmap( 0, ( st.st_size + iLoaderSize ), PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0 );

	memcpy ( &ehdr, dwAddress, sizeof( Elf32_Ehdr ) );

	printf( "- checking Binary format\n");

	if( ehdr.e_machine != EM_386 || ehdr.e_ident[EI_CLASS] != ELFCLASS32 )
    {
        printf( "* Error: Something wrong with Binary!\n");
        return -1;
    }
    else
    {
        printf( "  Ok!\n" );
    }

    printf( "- Old Entrypoint: 0x%X \n", ehdr.e_entry );
    dwOldEntry = ehdr.e_entry;

    printf( "- Searching for .text Section...\n" );

    void * shadd = dwAddress + ehdr.e_shoff;

    StringTable = ( Elf32_Shdr * )( shadd + ehdr.e_shstrndx * ehdr.e_shentsize);

    for( int x = 0; x < ehdr.e_shnum; ++x )
    {
        memcpy( &shdr, shadd, sizeof( Elf32_Shdr ) );

        szSectionName = ( dwAddress + StringTable->sh_offset ) + shdr.sh_name;

        if( bTextFound == true )
        {
            shdr.sh_addr = shdr.sh_addr + ( iLoaderSize + 1 );
            shdr.sh_offset = shdr.sh_offset + ( iLoaderSize + 1 );

            memcpy( shadd, &shdr, sizeof( Elf32_Shdr ) );
        }

        if( strcmp( ".text", szSectionName ) == NULL )
        {
            printf( "- Found .text Section!\n" );
            printf( "  Address: 0x%X\n", shdr.sh_addr );
            printf( "  Size: 0x%X\n", shdr.sh_size );

            shdr.sh_size = shdr.sh_size + iLoaderSize + 1;

            printf( "- Overwrite SECTION header\n" );
            memcpy( shadd, &shdr, sizeof( Elf32_Shdr ) );

            dwStartEncrypt = dwAddress + shdr.sh_offset;
            EncryptSize  = shdr.sh_size;

            printf( "- Encrypt .text Section\n");
            printf( "  Virtual Address: 0x%X\n", dwStartEncrypt );

            char * TextBuff = new char[shdr.sh_size + 1];

            memcpy( TextBuff, dwStartEncrypt, shdr.sh_size );

            dwStartEncrypt = TextBuff;

            Crypt( dwStartEncrypt, shdr.sh_size );

            dwStartEncrypt = dwAddress + shdr.sh_offset;
            dwSectionSize = shdr.sh_size;

            memcpy( dwStartEncrypt, TextBuff, shdr.sh_size );

            bTextFound = true;
        }

        shadd = shadd + ehdr.e_shentsize;
        dwSectionOffset = shdr.sh_offset;
    }

    printf( "- Searching for NOTE header...\n" );

    void * phadd = dwAddress + ehdr.e_phoff;

    for( int i = 0; i < ehdr.e_phnum; ++i )
    {
        memcpy( &phdr, phadd, sizeof( Elf32_Phdr ) );

        if( phdr.p_type == PT_LOAD )
        {

        }
        else if( phdr.p_type == PT_NOTE )
        {
            printf( "- Found NOTE header!\n");
            printf( "  Offset: 0x%X\n", phdr.p_offset );
            printf( "  Address: 0x%X\n", phdr.p_paddr );

            bNoteFound = true;

            dwBaseAddress = ( phdr.p_paddr - phdr.p_offset );

            phdr.p_type  = PT_LOAD;
            phdr.p_flags = PF_R | PF_X;
            phdr.p_align = 0x1000;

            printf( "- Overwrite NOTE header\n" );
            memcpy( phadd, &phdr, sizeof( Elf32_Phdr ) );

            dwNewEntry = dwAddress + phdr.p_offset;
            printf( "  Virtual Address: 0x%X\n", dwNewEntry );

            printf( "- Write LOADER to Memory\n");

            char * filebuff = new char[iLoaderSize + 1];
            memcpy( filebuff, PRE_LOADER, iLoaderSize );

            memcpy( ( filebuff + 0x5F ), &dwOldEntry, 4 );

            memcpy( ( filebuff + 0x63 ), &dwSectionSize, 4 );

            printf("  LOADER Size: %u\r\n", iLoaderSize );

            void * test = ( dwAddress + dwSectionOffset ) + dwSectionSize;

            dwNewEntry = dwStartEncrypt + dwSectionSize;

            memcpy( dwNewEntry, filebuff, iLoaderSize );

            ehdr.e_entry = dwOldEntry + dwSectionSize;//( dwBaseAddress + dwSectionOffset ) + dwSectionSize;
        }

        phadd = phadd + ehdr.e_phentsize;
    }

    if( !bNoteFound )
    {
        printf( "* Note header not found!\n" );
        return -1;
    }

    printf( "- Overwrite ELF header\n");
    memcpy( dwAddress, &ehdr, sizeof( Elf32_Ehdr ) );

    printf( "- Write everything to Binary file\n" );
    write( fd, dwAddress, ( st.st_size + iLoaderSize ) );

    munmap( dwAddress, ( st.st_size + iLoaderSize ) );
    close( fd );

    printf( "- Done!\n");
    return 1;
}
