#include <ft_ssl.h>

# define HASH_LEN 20
# define BLOCK_LEN 64

//TODO : Handle key longer than BLOCK_LEN

char	*hmac_sha1_encode(void *str, int size, char *key)
{
	// char	ipad[64];
	// char	opad[64];
	char	out[41];
	char	*k_ipad;
	char	*k_opad;
	uint32_t	*file;
	void	*tmp;
	size_t		i;

	// ft_memset(ipad, 0x36, 64);
	// ft_memset(opad, 0x5C, 64);
	k_ipad = malloc(BLOCK_LEN);
	k_opad = malloc(BLOCK_LEN);
	i = 0;
	while (i < (BLOCK_LEN))
	{
		if (i < ft_strlen(key))
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

	bytes_to_char(file, out, HASH_LEN);
	// free(file);

	return (ft_strdup(out));
}

int	main_hmac_sha1(t_opt *opt)
{
	int	in_fd;
	int	out_fd;

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

	char *out = hmac_sha1_encode("The quick brown fox jumps over the lazy dog\n", 44, "key");

	ft_putendl(out);
	free(out);

	return (1);
}