/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_gen.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/05 22:05:28 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/05 22:06:09 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

char	*malloc_prec_zero_doux(size_t precision, t_arg *arg, char conversion)
{
	char		*output;
	size_t		pos;

	if (arg->flag_more && arg->flag_dot == 0 && \
		(conversion == 'd' || conversion == 'f'))
		return (ft_strdup("+0"));
	if (precision == 0)
		return (ft_strdup("0"));
	output = (char*)malloc(sizeof(char) * precision + 0 + 1);
	output[precision] = '\0';
	pos = 0;
	while (pos++ < precision)
		output[pos - 1] = '0';
	return (output);
}

void	transform_n(t_data *data, intmax_t *var_int_max)
{
	*var_int_max = data->len_so_far;
	data->current->output_arg = ft_strdup("");
}

void	transform_r_init_prec(size_t *prec, t_arg *arg)
{
	*prec = arg->precision;
	if (arg->flag_dot != 1)
		*prec = 64;
	if (*prec > 64)
		*prec = 64;
}

void	transform_r(t_arg *arg, int64_t byte)
{
	size_t		prec;
	char		*output;
	int64_t		tmp_int_64;
	size_t		count;

	transform_r_init_prec(&prec, arg);
	if (prec == 0)
		return ;
	output = (char *)malloc(sizeof(char) * prec + 1);
	output[prec] = '\0';
	tmp_int_64 = 0x01;
	count = prec;
	while (count > 0)
	{
		if (byte & tmp_int_64)
			output[count - 1] = '1';
		else
			output[count - 1] = '0';
		tmp_int_64 *= 2;
		count--;
	}
	arg->output_arg = output;
}
