#include <ft_ssl.h>

static void init_decode_params(t_params_base64 *params)
{
	int	i;

	ft_memset(params->alphabet, -1, 255);
	i = 'A';
	while (i <= 'Z')
	{
		params->alphabet[i] = i - 'A';
		i++;
	}
	i = 'a';
	while (i <= 'z')
	{
		params->alphabet[i] = 26 + i - 'a';
		i++;
	}
	i = '0';
	while (i <= '9')
	{
		params->alphabet[52 + i - '0'] = i;
		i++;
	}
	params->alphabet['+'] = 62;
	params->alphabet['/'] = 63;
}

void			base64_decode_from_fd(t_opt *opt, int fd)
{
	t_params_base64	params;
}