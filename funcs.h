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

#ifndef FUNCS_H
#define FUNCS_H

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>

typedef unsigned char BYTE;

bool file_exists( const char * );
int iBackup( const char *, const char * );
void Crypt( BYTE *, unsigned long );
void DeCrypt( BYTE *, unsigned long );

#endif // FUNCS_H
