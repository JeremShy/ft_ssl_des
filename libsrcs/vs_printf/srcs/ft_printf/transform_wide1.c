/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_wide1.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 17:59:16 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 17:59:18 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

size_t			ft_wstrlen(wchar_t *str)
{
	size_t		length;

	length = 0;
	if (str)
		while (str[length])
			length++;
	return (length);
}

void			reset_output_for_precision(char *output, t_arg *arg, \
	size_t tmp_wlength)
{
	while (tmp_wlength < arg->output_wide_length)
	{
		output[arg->output_wide_length] = '\0';
		arg->output_wide_length--;
	}
}

void			transform_wide_s_init_struct(t_wide_s *wide_s, wchar_t *wide)
{
	size_t	length;

	length = ft_wstrlen(wide);
	wide_s->output = (char *)malloc(sizeof(char) * length * 4 + 1);
	wide_s->pos = 0;
	wide_s->tmp_wlength = 0;
}

static void		wide_string_return_norme(t_data *data, int8_t flag_return)
{
	if (flag_return == 1)
		data->current->output_arg = ft_strdup("(null)");
	else
		data->error = 1;
}

void			transform_wide_s(t_data *data, t_arg *arg, wchar_t *wide)
{
	t_wide_s	wide_s;

	if (wide == NULL)
		return (wide_string_return_norme(data, 1));
	transform_wide_s_init_struct(&wide_s, wide);
	arg->output_wide_length = 0;
	while (wide[wide_s.pos])
	{
		wide_s.tmp_wlength = arg->output_wide_length;
		if ((arg->output_wide_length += get_wchar1(\
			wide[wide_s.pos], wide_s.output, arg->output_wide_length)) == 0)
			return (wide_string_return_norme(data, 0));
		if (arg->flag_asterisk == 0 && arg->flag_dot == 1 && \
			arg->output_wide_length > arg->precision)
		{
			reset_output_for_precision(wide_s.output, arg, wide_s.tmp_wlength);
			break ;
		}
		wide_s.pos++;
	}
	wide_s.output[arg->output_wide_length] = '\0';
	arg->output_arg = wide_s.output;
	arg->output_wide_length = arg->output_wide_length;
}
