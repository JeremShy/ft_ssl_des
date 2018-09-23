#include <ft_ssl.h>

# define HASH_LEN 20
# define BLOCK_LEN 64

//TODO : Handle key longer than BLOCK_LEN

unsigned char	*hmac_sha1_encode(const void *str, int size, const unsigned char *key, size_t keylen)
{
	char	k_ipad[BLOCK_LEN];
	char	k_opad[BLOCK_LEN];
	uint32_t	*file;
	void	*tmp;
	size_t		i;

	tmp = NULL;
	if (keylen >= BLOCK_LEN)
	{
		tmp = sha1_encode(key, keylen);
		key = tmp;
		keylen = HASH_LEN;
	}
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
	if (tmp)
		free(tmp);
	file = malloc(BLOCK_LEN + size);
	ft_memcpy(file, k_ipad, BLOCK_LEN);
	ft_memcpy((void*)file + BLOCK_LEN, str, size);
	tmp = file;

	file = sha1_encode(file, BLOCK_LEN + size); // h((k ^ ipad) || m)

	free(tmp);

	tmp = file;
	file = malloc(BLOCK_LEN + HASH_LEN);
	ft_memcpy(file, k_opad, BLOCK_LEN);
	ft_memcpy((void*)file + BLOCK_LEN, tmp, HASH_LEN);

	free(tmp);

	tmp = file;
	file = sha1_encode(file, BLOCK_LEN + HASH_LEN);
	free(tmp);

	return (void*)(file);
}

int	main_hmac_sha1(t_opt *opt)
{
	int	in_fd;
	int	out_fd;
	char	*file;
	unsigned char	*hash;
	char	str[HASH_LEN * 2 + 1];
	int		r;

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
	file = get_file(in_fd, &r);
	hash = hmac_sha1_encode(file, r, (void*)opt->k_option, ft_strlen(opt->k_option));
	bytes_to_char((void*)hash, str, HASH_LEN);
	ft_putendl_fd(str, out_fd);
	free(file);
	free(hash);

	return (1);
}