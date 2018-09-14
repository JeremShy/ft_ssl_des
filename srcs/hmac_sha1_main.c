#include <ft_ssl.h>

char	*hmac_sha1_encode(void *str, int size, char *key)
{
	// char	ipad[64];
	// char	opad[64];
	char	*out;
	char	*k_ipad;
	char	*k_opad;
	char	*file;
	char	*tmp;
	size_t	len;
	int		i;

	// ft_memset(ipad, 0x36, 64);
	// ft_memset(opad, 0x5C, 64);
	len = ft_strlen(key) >= 64 ? ft_strlen(key) : 64;
	k_ipad = malloc(len);
	k_opad = malloc(len);
	i = 0;
	while (i < (len))
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
	tmp = k_ipad;
	k_ipad = sha1_encode(k_ipad, len);
	free(tmp);
	file = malloc(len);
	while (i < (len))
	{
		file[i] = k_opad | k_ipad | 
	}
	return (NULL);
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

	return (1);
}