/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   flag.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/01 19:53:07 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/01 19:58:54 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int8_t	verif_flag_already_used(t_data *data, char flag)
{
	if (flag == '.')
	{
		if (data->current->flag_dot == 1)
		{
			data->error = 2;
			return (0);
		}
		data->current->flag_dot = 1;
		if (data->current->flag_zero > 0)
		{
			data->current->flag_zero = 0;
			data->current->flag_zero_weird = 1;
		}
		return (1);
	}
	return (0);
}

void	flag_dot_prec(t_data *data)
{
	size_t	precision;
	size_t	tmp_move_in_arg;
	char	numeral;

	precision = 0;
	tmp_move_in_arg = data->move_in_arg - 1;
	while (ft_isdigit((numeral = data->format\
		[data->format_pos + data->move_in_arg])))
	{
		precision *= 10;
		precision += (int)numeral - 48;
		data->move_in_arg++;
	}
	if (tmp_move_in_arg != data->move_in_arg)
		data->move_in_arg--;
	data->current->precision = precision;
}

void	flag_dot(t_data *data)
{
	int		arg_wildcard;

	++data->move_in_arg;
	if (data->format[data->format_pos + data->move_in_arg] == '*')
	{
		arg_wildcard = va_arg(data->ap, int);
		if (arg_wildcard < 0)
		{
			data->current->flag_zero = 1;
			data->current->flag_asterisk = 1;
		}
		else
			data->current->precision = (size_t)arg_wildcard;
		return ;
	}
	flag_dot_prec(data);
}

void	flag_width_nb(t_data *data)
{
	size_t	width;
	char	numeral;
	size_t	tmp_move_in_arg;

	width = 0;
	tmp_move_in_arg = data->move_in_arg;
	while (ft_isdigit((numeral = data->format\
		[data->format_pos + data->move_in_arg])))
	{
		width *= 10;
		width += (int)numeral - 48;
		data->move_in_arg++;
	}
	if (tmp_move_in_arg != data->move_in_arg)
		data->move_in_arg--;
	data->current->width = width;
}
