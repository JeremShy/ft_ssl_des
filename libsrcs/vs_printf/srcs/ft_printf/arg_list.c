/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   arg_list.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/01 16:42:21 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/01 16:55:49 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	print_output_simple(t_arg *arg, t_data *data)
{
	write(arg->tmp_fd, data->format_mod + arg->before_arg, \
		ft_strlen(data->format_mod + arg->before_arg));
	if (arg->output_wide_length > 0)
	{
		write(arg->fd, arg->output_arg, arg->output_wide_length);
		free(arg->output_arg_wide);
	}
	else
		write(arg->fd, arg->output_arg, arg->output_length);
}

void	print_output_width(t_arg *arg, t_data *data)
{
	write(arg->tmp_fd, data->format_mod + arg->before_arg, \
		ft_strlen(data->format_mod + arg->before_arg));
	write(arg->fd, arg->output_width, ft_strlen(arg->output_width));
	if (arg->output_wide_length > 0)
	{
		write(arg->fd, arg->output_arg, arg->output_wide_length);
		free(arg->output_arg_wide);
	}
	else
		write(arg->fd, arg->output_arg, arg->output_length);
	free(arg->output_width);
}

void	print_output_width_reverse(t_arg *arg, t_data *data)
{
	write(arg->tmp_fd, data->format_mod + arg->before_arg, \
		ft_strlen(data->format_mod + arg->before_arg));
	if (arg->output_wide_length > 0)
	{
		write(arg->fd, arg->output_arg, arg->output_wide_length);
		free(arg->output_arg_wide);
	}
	else
		write(arg->fd, arg->output_arg, arg->output_length);
	write(arg->fd, arg->output_width, ft_strlen(arg->output_width));
	free(arg->output_width);
}

void	print_arg_and_free(t_data *data)
{
	t_arg		*arg_ptr_next;
	t_arg		*arg_ptr_current;

	arg_ptr_current = data->first;
	while (arg_ptr_current)
	{
		arg_ptr_next = arg_ptr_current->next;
		if (arg_ptr_current->output_width != NULL)
		{
			if (arg_ptr_current->flag_less == 0)
				print_output_width(arg_ptr_current, data);
			else
				print_output_width_reverse(arg_ptr_current, data);
		}
		else
			print_output_simple(arg_ptr_current, data);
		if (arg_ptr_current->output_arg != NULL)
			free(arg_ptr_current->output_arg);
		free(arg_ptr_current);
		arg_ptr_current = arg_ptr_next;
	}
	write(data->fd, data->format + data->tmp_format_pos, \
		ft_strlen(data->format + data->tmp_format_pos));
	if (data->color_set == 1)
		write(1, "\033[0m", 4);
}
