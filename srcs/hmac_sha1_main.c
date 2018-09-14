#include <ft_ssl.h>

# define HASH_LEN 40
# define BLOCK_LEN 64

char	*hmac_sha1_encode(void *str, int size, char *key)
{
	// char	ipad[64];
	// char	opad[64];
	char	*out;
	char	*k_ipad;
	char	*k_opad;
	char	*file;
	char	*tmp;
	int		i;

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
			k_ipad[i] = 0x36;
			k_opad[i] = 0x5c;
		}
		i++;
	}
	file = malloc(BLOCK_LEN + size);
	ft_memcpy(file, k_ipad, BLOCK_LEN);
	ft_memcpy(file + BLOCK_LEN, str, size);

	tmp = file;
	file = sha1_encode(file, BLOCK_LEN + size);
	free(tmp);
	free(k_ipad);

	tmp = file;
	file = malloc(BLOCK_LEN + HASH_LEN);
	ft_memcpy(file, k_opad, BLOCK_LEN);
	ft_memcpy(file + BLOCK_LEN, tmp, HASH_LEN);
	free(tmp);

	tmp = file;
	file = sha1_encode(file, BLOCK_LEN + HASH_LEN);
	free(tmp);

	printf("file : %s\n", file);

	return (file);
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

	hmac_sha1_encode("", 0, "");

	return (1);
}