/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   flag_color1.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/05 18:41:59 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/05 18:42:11 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	flag_color_move_in_arg(t_data *data, const char *color, size_t move)
{
	if (data->current->output_arg == NULL)
		data->current->output_arg = ft_strdup(color);
	else
		data->current->output_arg = ft_strjoinaf1(\
			data->current->output_arg, color);
	data->move_in_arg += move;
}

void	flag_color_fg2(t_data *data, const char *arguments)
{
	if (ft_strncmp("LCYAN", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_LCYAN, 5);
	else if (ft_strncmp("LGRAY", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_LGRAY, 5);
	else if (ft_strncmp("YELLOW", arguments, 6) == 0)
		flag_color_move_in_arg(data, FG_YELLOW, 6);
	else if (ft_strncmp("LGREEN", arguments, 6) == 0)
		flag_color_move_in_arg(data, FG_LGREEN, 6);
	else if (ft_strncmp("DEFAULT", arguments, 7) == 0)
		flag_color_move_in_arg(data, FG_DEFAULT, 7);
	else if (ft_strncmp("MAGENTA", arguments, 7) == 0)
		flag_color_move_in_arg(data, FG_MAGENTA, 7);
	else if (ft_strncmp("LYELLOW", arguments, 7) == 0)
		flag_color_move_in_arg(data, FG_LYELLOW, 7);
	else if (ft_strncmp("LMAGENTA", arguments, 8) == 0)
		flag_color_move_in_arg(data, FG_LMAGENTA, 8);
	else
		data->error = 1;
}

void	flag_color_fg1(t_data *data, const char *arguments)
{
	if (ft_strncmp("RED", arguments, 3) == 0)
		flag_color_move_in_arg(data, FG_RED, 3);
	else if (ft_strncmp("BLUE", arguments, 4) == 0)
		flag_color_move_in_arg(data, FG_BLUE, 4);
	else if (ft_strncmp("CYAN", arguments, 4) == 0)
		flag_color_move_in_arg(data, FG_CYAN, 4);
	else if (ft_strncmp("LRED", arguments, 4) == 0)
		flag_color_move_in_arg(data, FG_LRED, 4);
	else if (ft_strncmp("BLACK", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_BLACK, 5);
	else if (ft_strncmp("GREEN", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_GREEN, 5);
	else if (ft_strncmp("WHITE", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_WHITE, 5);
	else if (ft_strncmp("DGRAY", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_DGRAY, 5);
	else if (ft_strncmp("LBLUE", arguments, 5) == 0)
		flag_color_move_in_arg(data, FG_LBLUE, 5);
	else
		flag_color_fg2(data, arguments);
}

void	flag_color_bg2(t_data *data, const char *arguments)
{
	if (ft_strncmp("LCYAN", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_LCYAN, 5);
	else if (ft_strncmp("LGRAY", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_LGRAY, 5);
	else if (ft_strncmp("YELLOW", arguments, 6) == 0)
		flag_color_move_in_arg(data, BG_YELLOW, 6);
	else if (ft_strncmp("LGREEN", arguments, 6) == 0)
		flag_color_move_in_arg(data, BG_LGREEN, 6);
	else if (ft_strncmp("DEFAULT", arguments, 7) == 0)
		flag_color_move_in_arg(data, BG_DEFAULT, 7);
	else if (ft_strncmp("MAGENTA", arguments, 7) == 0)
		flag_color_move_in_arg(data, BG_MAGENTA, 7);
	else if (ft_strncmp("LYELLOW", arguments, 7) == 0)
		flag_color_move_in_arg(data, BG_LYELLOW, 7);
	else if (ft_strncmp("LMAGENTA", arguments, 8) == 0)
		flag_color_move_in_arg(data, BG_LMAGENTA, 8);
	else
		data->error = 1;
}

void	flag_color_bg1(t_data *data, const char *arguments)
{
	if (ft_strncmp("RED", arguments, 3) == 0)
		flag_color_move_in_arg(data, BG_RED, 3);
	else if (ft_strncmp("BLUE", arguments, 4) == 0)
		flag_color_move_in_arg(data, BG_BLUE, 4);
	else if (ft_strncmp("CYAN", arguments, 4) == 0)
		flag_color_move_in_arg(data, BG_CYAN, 4);
	else if (ft_strncmp("LRED", arguments, 4) == 0)
		flag_color_move_in_arg(data, BG_LRED, 4);
	else if (ft_strncmp("BLACK", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_BLACK, 5);
	else if (ft_strncmp("GREEN", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_GREEN, 5);
	else if (ft_strncmp("WHITE", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_WHITE, 5);
	else if (ft_strncmp("DGRAY", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_DGRAY, 5);
	else if (ft_strncmp("LBLUE", arguments, 5) == 0)
		flag_color_move_in_arg(data, BG_LBLUE, 5);
	else
		flag_color_bg2(data, arguments);
}
