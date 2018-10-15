/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser_conv.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 22:40:00 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 22:40:02 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int8_t		parser_conv5(t_data *data, char char_analyse)
{
	if (char_analyse == 'r')
	{
		transform_r(data->current, (int64_t)va_arg(data->ap, int64_t));
		return (0);
	}
	return (1);
}

int8_t		parser_conv4(t_data *data, char char_analyse)
{
	if (char_analyse == 'C')
	{
		transform_wide_c(data, data->current, \
			(wchar_t)va_arg(data->ap, wint_t));
		return (0);
	}
	else if (char_analyse == 'S')
	{
		transform_wide_s(data, data->current, va_arg(data->ap, wchar_t *));
		return (0);
	}
	else if (char_analyse == 'p')
	{
		transform_p(data->current, va_arg(data->ap, void *));
		return (0);
	}
	else if (char_analyse == 'n')
	{
		transform_n(data, (intmax_t *)va_arg(data->ap, int *));
		return (0);
	}
	else
		return (parser_conv5(data, char_analyse));
}

int8_t		parser_conv3(t_data *data, char char_analyse)
{
	if (char_analyse == 'O')
	{
		transform_o(data->current, (long int)va_arg(data->ap, long int));
		return (0);
	}
	else if (char_analyse == 'U')
	{
		transform_u(data->current, (long int)va_arg(data->ap, long int));
		return (0);
	}
	else if (char_analyse == 'c')
	{
		transform_c(data->current, va_arg(data->ap, int));
		return (0);
	}
	else if (char_analyse == 's')
	{
		transform_s(data->current, va_arg(data->ap, char *));
		return (0);
	}
	else
		return (parser_conv4(data, char_analyse));
}

int8_t		parser_conv2(t_data *data, char char_analyse)
{
	if (char_analyse == 'u')
	{
		transform_u(data->current, (unsigned int)va_arg(data->ap, int));
		return (0);
	}
	else if (char_analyse == 'x')
	{
		transform_x(data->current, (unsigned int)va_arg(data->ap, int));
		return (0);
	}
	else if (char_analyse == 'X')
	{
		transform_big_x(data->current, (unsigned int)va_arg(data->ap, int));
		return (0);
	}
	else if (char_analyse == 'D')
	{
		transform_d(data->current, (long int)va_arg(data->ap, long int));
		return (0);
	}
	else
		return (parser_conv3(data, char_analyse));
}

int8_t		parser_conv1(t_data *data, char char_analyse)
{
	if (char_analyse == 'd' || char_analyse == 'i')
	{
		transform_d(data->current, va_arg(data->ap, int));
		return (0);
	}
	else if (char_analyse == 'f' || char_analyse == 'F')
	{
		if (!data->current->flag_dot)
		{
			data->current->precision = 6;
		}
		transform_f(data->current, va_arg(data->ap, double));
		return (0);
	}
	else if (char_analyse == 'o')
	{
		transform_o(data->current, (unsigned int)va_arg(data->ap, int));
		return (0);
	}
	else
		return (parser_conv2(data, char_analyse));
}
