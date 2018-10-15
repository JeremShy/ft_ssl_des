/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/27 18:52:23 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 18:05:12 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	init_data_and_var(t_data *data, const char *restrict format)
{
	data->format = format;
	data->format_mod = (char *)ft_strdup(format);
	data->format_pos = 0;
	data->tmp_format_pos = 0;
	data->error = 0;
	data->len_so_far = 0;
	data->color_set = 0;
	data->fd = 1;
	data->first = NULL;
	data->current = NULL;
}

void	ft_printf_error_reset(t_data *data)
{
	if (data->error != 100)
		data->format_pos--;
	data->error = 0;
}

int		ft_printf(const char *restrict format, ...)
{
	t_data		data;
	size_t		length;

	init_data_and_var(&data, format);
	va_start(data.ap, format);
	while (format[data.format_pos] != '\0')
	{
		if (format[data.format_pos] == '%')
		{
			data.format_pos += parse_and_move_format(&data);
			if (data.error > 0)
				ft_printf_error_reset(&data);
			data.tmp_format_pos = data.format_pos + 1;
			data.format_pos++;
			continue ;
		}
		data.format_pos++;
		data.len_so_far++;
	}
	print_arg_and_free(&data);
	length = data.len_so_far;
	free(data.format_mod);
	va_end(data.ap);
	return (length);
}
