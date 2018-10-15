/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser_mod.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 20:57:20 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 20:57:22 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int8_t		parser_mod3(t_data *data, char char_analyse)
{
	if (char_analyse == 'j')
	{
		detect_length_mod_j1(data, \
			data->format[data->format_pos + data->move_in_arg + 1]);
		data->move_in_arg++;
		return (0);
	}
	else if (char_analyse == 'z')
	{
		detect_length_mod_z1(data, \
			data->format[data->format_pos + data->move_in_arg + 1]);
		data->move_in_arg++;
		return (0);
	}
	return (1);
}

int8_t		parser_mod2(t_data *data, char char_analyse)
{
	if (char_analyse == 'l')
	{
		if (data->format[data->format_pos + data->move_in_arg + 1] == 'l')
		{
			detect_length_mod_ll1(data, \
				data->format[data->format_pos + data->move_in_arg + 2]);
			data->move_in_arg += 2;
			return (0);
		}
		detect_length_mod_l1(data, \
			data->format[data->format_pos + data->move_in_arg + 1]);
		data->move_in_arg++;
		return (0);
	}
	else
		return (parser_mod3(data, char_analyse));
}

int8_t		parser_mod1(t_data *data, char char_analyse)
{
	if (char_analyse == 'h')
	{
		if (data->format[data->format_pos + data->move_in_arg + 1] == 'h')
		{
			detect_length_mod_hh1(data, \
				data->format[data->format_pos + data->move_in_arg + 2]);
			data->move_in_arg += 2;
			return (0);
		}
		detect_length_mod_h1(data, \
			data->format[data->format_pos + data->move_in_arg + 1]);
		data->move_in_arg++;
		return (0);
	}
	else
		return (parser_mod2(data, char_analyse));
}
