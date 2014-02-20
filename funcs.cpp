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

bool file_exists( const char * filename )
{
    if( FILE * file = fopen( filename, "r" ) )
    {
        fclose( file );
        return true;
    }
    return false;
}

int iBackup( const char *to, const char *from )
{
    int fd_to, fd_from;
    char buf[4096];
    ssize_t nread;
    int saved_errno;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0)
        return -1;

    fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd_to < 0)
        goto out_error;

    while (nread = read(fd_from, buf, sizeof buf), nread > 0)
    {
        char *out_ptr = buf;
        ssize_t nwritten;

        do {
            nwritten = write(fd_to, out_ptr, nread);

            if (nwritten >= 0)
            {
                nread -= nwritten;
                out_ptr += nwritten;
            }
            else if (errno != EINTR)
            {
                goto out_error;
            }
        } while (nread > 0);
    }

    if (nread == 0)
    {
        if (close(fd_to) < 0)
        {
            fd_to = -1;
            goto out_error;
        }
        close(fd_from);

        /* Success! */
        return 0;
    }

  out_error:
    saved_errno = errno;

    close(fd_from);
    if (fd_to >= 0)
        close(fd_to);

    errno = saved_errno;
    return -1;
}

void Crypt( BYTE * bBuffer, unsigned long iSize )
{
	BYTE bXorByte = 0x57;
	BYTE bDecoded;

	for( unsigned long i = 0; i < iSize; i++ )
	{
		bDecoded = bBuffer[i] ^ bXorByte;
		bXorByte += bBuffer[i] + 0x57;
		bBuffer[i] = bDecoded;
	}
}

void DeCrypt( BYTE *bBuffer, unsigned long iSize )
{
	BYTE bXorByte = 0x57;

	for( unsigned long i = 0; i < iSize; i++ )
	{
		bBuffer[i] = bBuffer[i] ^ bXorByte;
		bXorByte += bBuffer[i] + 0x57;
	}
}
