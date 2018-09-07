#include <ft_ssl.h>
#define BUFF_SIZE_BASE64 48

static void	init_params(t_params_base64 *params)
{
	int	i;

	i = 'A';
	while (i <= 'Z')
	{
		params->alphabet[i - 'A'] = i;
		i++;
	}
	i = 'a';
	while (i <= 'z')
	{
		params->alphabet[26 + i - 'a'] = i;
		i++;
	}
	i = '0';
	while (i <= '9')
	{
		params->alphabet[52 + i - '0'] = i;
		i++;
	}
	params->alphabet[62] = '+';
	params->alphabet[63] = '/';
}

static int8_t	get_current_value(char buffer[BUFF_SIZE_BASE64], int i)
{
	int	index_debut;
	int	index_fin;
	char	c_debut;
	char	c_fin;

	index_debut = i * 6 / 8;
	index_fin = (((i + 1) * 6 - 1) / 8);
	c_debut = buffer[index_debut];
	c_fin = buffer[index_fin];

	// printf ("i = %d, index_debut = %d, index_fin = %d\n", i, index_debut, index_fin);
	if (i % 4 == 0)
		return ((c_debut & 252) >> 2);
	else if (i % 4 == 1)
		return (((c_debut & 3) << 4) | ((c_fin & 240)) >> 4);
	else if (i % 4 == 2)
		return (((c_debut & 15) << 2) | ((c_fin & 192) >> 6));
	else
		return (c_fin & 63);
}
/*
	** 01234567 01234567 01234567		(...)
	** 012345 670123 456701 234567	(...)

	i % 4 == 0 : bits 012345 // 0 - 0
	i % 4 == 1 : bits 670123 // 0 - 1
	i % 4 == 2 : bits 456701 // 1 - 2
	i % 4 == 3 : bits 234567 // 2 - 3


	codon 5 : 4 * 6 = 24->29 bit
	24 / 8 = 3e octet
	29 / 8 = 3e octet
*/

void	print_last_bits(t_params_base64 *params, char buffer[BUFF_SIZE_BASE64], int i, int r)
{
	int8_t	tmp[4];

	tmp[0] = 0;
	tmp[1] = 0;
	tmp[2] = 0;
	tmp[3] = 0;

	if (r * 8 - i * 6 == 16)
	{
		tmp[0] = buffer[i * 6 / 8];
		tmp[1] = buffer[i * 6 / 8 + 1];
		tmp[2] = 0;
		ft_putchar(params->alphabet[get_current_value((char*)tmp, 0)]);
		ft_putchar(params->alphabet[get_current_value((char*)tmp, 1)]);
		ft_putchar(params->alphabet[get_current_value((char*)tmp, 2)]);
		ft_putchar('=');
	}
	else if (r * 8 - i * 6 == 8)
	{
		tmp[0] = buffer[i * 6 / 8];
		tmp[1] = 0;
		ft_putchar(params->alphabet[get_current_value((char*)tmp, 0)]);
		ft_putchar(params->alphabet[get_current_value((char*)tmp, 1)]);
		ft_putchar('=');
		ft_putchar('=');
	}
	else
	{
		printf("ERROR\n");
	}
}

static void	print_four_chars(t_params_base64 *params, char buffer[BUFF_SIZE_BASE64], int *i)
{
	int	j;
	int8_t	current_value;

	j = 0;
	while (j < 4)
	{
			current_value = get_current_value(buffer, *i);
			ft_putchar(params->alphabet[current_value]);
			(*i)++;
			j++;
	}
}

void	base64_encode_from_fd(t_opt *opt, int fd)
{
	t_params_base64	params;
	char	buffer[BUFF_SIZE_BASE64];
	int		r;
	int		i;
	int8_t	equals_nbr;

	init_params(&params);
	while ((r = read(fd, buffer, BUFF_SIZE_BASE64)) > 0)
	{
		i = 0;
		while (1)
		{
			if (r * 8 - i * 6 < 24)
				break;
			else
				print_four_chars(&params, buffer, &i);

		}
		if (r < BUFF_SIZE_BASE64)
			break;
		ft_putchar('\n');
	}
	if (r < 0)
		ft_putstr_fd("Error while reading the input.\n", 2);
	if (r * 8 - i * 6 < 24 && r * 8 - i * 6 != 0)
		print_last_bits(&params, buffer, i, r);
	ft_putchar('\n');
}