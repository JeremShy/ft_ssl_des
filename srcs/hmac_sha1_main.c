#include <ft_ssl.h>

# define HASH_LEN 20
# define BLOCK_LEN 64

//TODO : Handle key longer than BLOCK_LEN

unsigned char	*hmac_sha1_encode(const void *str, int size, unsigned char *key, size_t keylen)
{
	char	*k_ipad;
	char	*k_opad;
	uint32_t	*file;
	void	*tmp;
	size_t		i;

	if (keylen >= BLOCK_LEN)
	{
		ft_putendl("You should have handled that.");
		exit(EXIT_FAILURE);
	}
	k_ipad = malloc(BLOCK_LEN);
	k_opad = malloc(BLOCK_LEN);
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

	file = malloc(BLOCK_LEN + size);
	ft_memcpy(file, k_ipad, BLOCK_LEN);
	ft_memcpy((void*)file + BLOCK_LEN, str, size);
	tmp = file;

	file = sha1_encode(file, BLOCK_LEN + size); // h((k ^ ipad) || m)

	free(tmp);
	free(k_ipad);

	tmp = file;
	file = malloc(BLOCK_LEN + HASH_LEN);
	ft_memcpy(file, k_opad, BLOCK_LEN);
	ft_memcpy((void*)file + BLOCK_LEN, tmp, HASH_LEN);

	free(tmp);
	free(k_opad);

	tmp = file;
	file = sha1_encode(file, BLOCK_LEN + HASH_LEN);
	free(tmp);

	return (void*)(file);
}

int	main_hmac_sha1(t_opt *opt)
{
	int	in_fd;
	int	out_fd;
	char	out[41];

	if (!(opt->flags & K_OPT) || !opt->k_option)
	{
		ft_putendl_fd("Key needed", 2);
		return (0);
	}

	if (opt->flags & I_OPT)
	{
		if (!opt->i_option)	
			return (0);
		in_fd = open(opt->i_option, O_RDONLY);
		if (in_fd == -1)
			return (0);
	}
	else
		in_fd = 0;
	if (opt->flags & O_OPT)
	{
		if (!opt->o_option)
			return (0);
		out_fd = open(opt->o_option, O_RDONLY);
		if (out_fd == -1)
			return (0);
	}
	else
		out_fd = 1;

	unsigned char key[100];
	ft_memset(key, 0xaa, 90);
	// ft_memcpy(key, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25);
	unsigned char data[100];
	// ft_memset(data, 0xcd, 50);
	ft_memcpy(data, "Test With Truncation", 20);

	unsigned char *encoded = hmac_sha1_encode(data, 20, key, 90);
	bytes_to_char((uint32_t*)encoded, out, 20);
	ft_putendl(out);
	free(encoded);



	return (1);
}