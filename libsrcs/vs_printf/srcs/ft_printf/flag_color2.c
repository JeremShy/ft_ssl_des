/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   flag_color2.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/05 18:42:15 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/05 18:42:20 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	flag_color_no(t_data *data, const char *arguments)
{
	if (ft_strncmp("BLINK", arguments, 5) == 0)
		flag_color_move_in_arg(data, NO_BLINK, 5);
	else if (ft_strncmp("REVERSE", arguments, 7) == 0)
		flag_color_move_in_arg(data, NO_REVERSE, 7);
	else if (ft_strncmp("STANDOUT", arguments, 8) == 0)
		flag_color_move_in_arg(data, NO_STANDOUT, 8);
	else if (ft_strncmp("UNDERLINED", arguments, 10) == 0)
		flag_color_move_in_arg(data, NO_UNDERLINED, 10);
	else
		data->error = 1;
}

int8_t	flag_color_other(t_data *data, const char *arguments)
{
	if (ft_strncmp("BOLD", arguments, 4) == 0)
		flag_color_move_in_arg(data, BOLD, 4);
	else if (ft_strncmp("FAINT", arguments, 5) == 0)
		flag_color_move_in_arg(data, FAINT, 5);
	else if (ft_strncmp("BLINK", arguments, 5) == 0)
		flag_color_move_in_arg(data, BLINK, 5);
	else if (ft_strncmp("HIDDEN", arguments, 6) == 0)
		flag_color_move_in_arg(data, HIDDEN, 6);
	else if (ft_strncmp("REVERSE", arguments, 7) == 0)
		flag_color_move_in_arg(data, REVERSE, 7);
	else if (ft_strncmp("CS_RESET", arguments, 8) == 0)
		flag_color_move_in_arg(data, CS_RESET, 8);
	else if (ft_strncmp("UNDERLINE", arguments, 9) == 0)
		flag_color_move_in_arg(data, UNDERLINE, 9);
	else
		return (1);
	return (0);
}

void	find_pattern_color(t_data *data, const char *arguments)
{
	if (ft_strncmp("FG_", arguments, 3) == 0)
	{
		data->move_in_arg += 3;
		flag_color_fg1(data, arguments + 3);
	}
	else if (ft_strncmp("BG_", arguments, 3) == 0)
	{
		data->move_in_arg += 3;
		flag_color_bg1(data, arguments + 3);
	}
	else if (ft_strncmp("NO_", arguments, 3) == 0)
	{
		data->move_in_arg += 3;
		flag_color_no(data, arguments + 3);
	}
	else if (flag_color_other(data, arguments) == 1)
		data->error = 1;
}

void	flag_color_fd(t_data *data, const char *arguments)
{
	data->move_in_arg++;
	if (ft_strncmp("FD", arguments, 2) == 0)
	{
		data->current->fd = (uintmax_t)va_arg(data->ap, uintmax_t);
		data->fd = data->current->fd;
		data->move_in_arg += 2;
		return ;
	}
	else
		find_pattern_color(data, arguments);
	if (data->error != 0)
	{
		if (data->current->output_arg != NULL)
			data->current->output_arg[0] = '\0';
		data->move_in_arg = 1;
		return ;
	}
	data->color_set = 1;
}
