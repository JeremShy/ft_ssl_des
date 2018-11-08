#include <ft_ssl.h>

#define BLOCK_LEN 64

void			fill_ipad_opad(size_t keylen, char *k_ipad, char *k_opad,
	const unsigned char *key)
{
	size_t	i;

	i = 0;
	while (i < (BLOCK_LEN))
	{
		if (i < keylen)
		{
			k_ipad[i] = key[i] ^ 0x36;
			k_opad[i] = key[i] ^ 0x5c;
		}
		else
		{
			k_ipad[i] = 0 ^ 0x36;
			k_opad[i] = 0 ^ 0x5c;
		}
		i++;
	}
}
