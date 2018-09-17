#include <ft_ssl.h>

#define HLEN 20

/*
F is defined as the exclusive-or sum of the
         first c iterates of the underlying pseudorandom function PRF
         applied to the password P and the concatenation of the salt S
         and the block index i:

                   F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c

         where

                   U_1 = PRF (P, S || INT (i)) ,
                   U_2 = PRF (P, U_1) ,
                   ...
                   U_c = PRF (P, U_{c-1}) .

*/

void	f(t_pbkdf2_params *params, int cur)
{
	int		i;
	// unsigned char	block[HLEN];
	unsigned char	**blocks;
	void		*first_buffer;

	blocks = malloc(sizeof(unsigned char *) * params->iter);

	i = 0;
	while (i < params->iter)
	{
		if (i == 0)
		{
			first_buffer = malloc(params->salt_len + 4);
			ft_memcpy(first_buffer, params->salt, params->salt_len);
			*(uint32_t*)(first_buffer + params->salt_len) = end_conv_32(cur);

			blocks[0] = (unsigned char*)hmac_sha1_encode((void*)params->password, params->pass_len, first_buffer, params->salt_len + 4);
			print_memory(params->password, params->pass_len);
			print_memory(first_buffer, params->salt_len + 4);
			free(first_buffer);
		}
		else
		{
			blocks[i] = hmac_sha1_encode(params->password, params->pass_len, blocks[i - 1], HLEN);
		}
		i++;
	}
	i = 1;
	while (i < params->iter)
	{
		int	j;
		j = 0;
		while (j < HLEN)
		{
			blocks[0][j] ^= (blocks[i])[j];
			j++;
		}
		i++;
	}
	print_memory(blocks[0], HLEN);
}

int	pbkdf2_hmac_sha1(t_pbkdf2_params *params)
{
	int	l;
	int	r;

	l = (int)ceil(params->dklen / (double)HLEN);
	printf("l : %d\n", l);
	r = params->dklen - (l - 1) * HLEN;
	printf("r : %d\n", r);
	f(params, 1);

	return (1);
}