/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/01 16:57:32 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/01 16:57:35 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	init_struct_arg_flag(t_arg *struct_ptr)
{
	struct_ptr->flag_width_nb = 0;
	struct_ptr->flag_width_wc = 0;
	struct_ptr->flag_asterisk = 0;
	struct_ptr->flag_hash = 0;
	struct_ptr->flag_zero = 0;
	struct_ptr->flag_zero_weird = 0;
	struct_ptr->flag_less = 0;
	struct_ptr->flag_more = 0;
	struct_ptr->flag_space = 0;
	struct_ptr->flag_dot = 0;
}

t_arg	*create_struct_arg(t_data *data)
{
	t_arg		*struct_ptr;

	struct_ptr = (t_arg*)malloc(sizeof(t_arg));
	struct_ptr->next = NULL;
	struct_ptr->before_arg = data->tmp_format_pos;
	struct_ptr->output_arg = NULL;
	struct_ptr->fd = data->fd;
	struct_ptr->tmp_fd = data->fd;
	struct_ptr->width = 0;
	struct_ptr->precision = 0;
	struct_ptr->type = 0;
	struct_ptr->output_arg_wide = NULL;
	struct_ptr->output_wide_length = 0;
	struct_ptr->output_width = NULL;
	struct_ptr->output_length = 0;
	init_struct_arg_flag(struct_ptr);
	return (struct_ptr);
}
