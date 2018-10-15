/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser_flag.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 22:35:39 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 22:35:41 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int8_t		parser_flag4(t_data *data, char char_analyse)
{
	if (char_analyse == '{' && data->move_in_arg == 1)
	{
		flag_color_fd(\
			data, data->format + data->format_pos + data->move_in_arg + 1);
		while (data->format[data->format_pos + data->move_in_arg] == ',')
			flag_color_fd(\
				data, data->format + data->format_pos + data->move_in_arg + 1);
		if (data->format[data->format_pos + data->move_in_arg] != '}' && \
			data->error == 0)
		{
			data->error = 1;
			data->len_so_far -= ft_strlen(data->current->output_arg);
			data->current->output_arg[0] = '\0';
			data->move_in_arg = 1;
		}
		return (0);
	}
	return (1);
}

int8_t		parser_flag3(t_data *data, char char_analyse)
{
	if (char_analyse == '%')
	{
		transform_c(data->current, '%');
		return (0);
	}
	else if (char_analyse == ' ')
	{
		data->current->flag_space = 1;
		return (-1);
	}
	else if (char_analyse == '+')
	{
		data->current->flag_more = 1;
		return (-1);
	}
	else if (char_analyse == '#')
	{
		data->current->flag_hash = 1;
		return (-1);
	}
	else
		return (parser_flag4(data, char_analyse));
}

int8_t		parser_flag2(t_data *data, char char_analyse)
{
	int tmp_int;

	if (char_analyse == '*')
	{
		data->current->flag_width_wc = 1;
		tmp_int = va_arg(data->ap, int);
		if (tmp_int < 0)
		{
			tmp_int = -tmp_int;
			data->current->flag_less = 1;
		}
		data->current->width = (size_t)tmp_int;
		return (-1);
	}
	else if (char_analyse == '-')
	{
		data->current->flag_less = 1;
		if (data->current->flag_zero > 0)
			data->current->flag_zero = 0;
		return (-1);
	}
	else
		return (parser_flag3(data, char_analyse));
}

int8_t		parser_flag1(t_data *data, char char_analyse)
{
	if (char_analyse == '.')
	{
		if (verif_flag_already_used(data, '.') == 0)
			return (0);
		flag_dot(data);
		return (-1);
	}
	else if (ft_isdigit(char_analyse))
	{
		if (char_analyse == '0' && data->current->flag_dot == 0 && \
			data->current->flag_less == 0)
		{
			data->current->flag_zero = 1;
			return (-1);
		}
		data->current->flag_width_nb = 1;
		flag_width_nb(data);
		return (-1);
	}
	else
		return (parser_flag2(data, char_analyse));
}
