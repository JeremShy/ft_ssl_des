#include <ft_ssl.h>

void		print_four_chars(t_params_base64 *params,
	char *buffer, int *i, int output_fd)
{
	int		j;
	int8_t	current_value;

	j = 0;
	while (j < 4)
	{
		current_value = gcv(buffer, *i);
		ft_putchar_fd(params->alphabet[current_value], output_fd);
		(*i)++;
		j++;
	}
}
