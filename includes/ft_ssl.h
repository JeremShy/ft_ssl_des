#ifndef FT_SSL_H
# define FT_SSL_H

# include <libft.h>
# include <fcntl.h>
# include <unistd.h>

// # define CSHIFT(nbr, s) (uint)(((nbr) << (s)) | (((nbr) & ((-1u) << (32 - (s)))) >> (32 - (s))))

// # define END_CONV_32(nbr) (uint)((nbr >> 24) | ((nbr & 0xFF0000) >> 8) | ((nbr & 0xFF00) << 8) | (nbr << 24))
//
// # define END_CONV_64(nbr) (uint64_t)(((uint64_t)(END_CONV_32(nbr >> 32)) << 32) | ((END_CONV_32((uint)nbr))) )
// # define END_CONV_64(nbr) (uint64_t)((END_CONV_32 ((uint)(((nbr & 0xffffffff00000000l)) >> 32))) | ((uint64_t)(END_CONV_32((uint)nbr)) << 32))

typedef struct s_params
{
	uint buffer[4];
	uint k;
	uint s;
	uint i;
	uint t[65];
	uint x[16];
}		t_params;

typedef uint	(*t_fghi) (uint, uint, uint);
typedef void (*t_f1234) (t_params*, t_fghi);

void print_memory(char *start, size_t size);

#endif
