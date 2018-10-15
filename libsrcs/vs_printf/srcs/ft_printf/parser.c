/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/27 18:52:23 by vsteffen          #+#    #+#             */
/*   Updated: 2016/11/17 17:37:23 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int8_t	detect_pattern(t_data *data, char char_analyse)
{
	int8_t		return_var;

	if ((return_var = parser_conv1(data, char_analyse)) != 1)
		return (return_var);
	else if ((return_var = parser_mod1(data, char_analyse)) != 1)
		return (return_var);
	else if ((return_var = parser_flag1(data, char_analyse)) != 1)
		return (return_var);
	else
	{
		data->error = 100;
		if (char_analyse != '\0')
		{
			data->current->output_arg = ft_strdup("q");
			data->current->output_arg[0] = \
				data->format_mod[data->format_pos + data->move_in_arg];
		}
		return (0);
	}
}

void	get_output_malloc_width_flag(t_arg *arg, char first_char_output, \
	char last_conv)
{
	if (arg->flag_space == 1 && arg->flag_zero == 1)
	{
		arg->output_width[0] = ' ';
		arg->output_arg[0] = '0';
	}
	if (arg->flag_zero > 0 && \
		(first_char_output == '+' || first_char_output == '-'))
	{
		arg->output_width[0] = first_char_output;
		arg->output_arg[0] = '0';
	}
	if (arg->flag_zero == 1 && arg->flag_hash == 1 && \
		arg->output_width[1] != '\0' && (last_conv == 'x' || last_conv == 'X'))
	{
		arg->output_width[1] = 'x';
		arg->output_arg[1] = '0';
	}
	if (arg->flag_zero == 1 && arg->output_width[1] != '\0' && last_conv == 'p')
	{
		arg->output_width[1] = 'x';
		arg->output_arg[1] = '0';
	}
}

void	get_output_malloc_width(t_arg *arg, char first_char_output, \
	char last_conv)
{
	size_t		pos;
	char		fill_width;

	arg->output_width = (char*)malloc(sizeof(char) * arg->width + 1);
	arg->output_width[arg->width] = '\0';
	pos = 0;
	fill_width = ' ';
	if (arg->flag_zero > 0 || (arg->flag_zero_weird == 1 && \
		(last_conv == 'c' || last_conv == 's' || last_conv == '%' \
		|| last_conv == 'Z' || last_conv == 'S')))
		fill_width = '0';
	while (pos++ < arg->width)
		arg->output_width[pos - 1] = fill_width;
	get_output_malloc_width_flag(arg, first_char_output, last_conv);
}

void	set_ptr_chained_list_and_init(t_data *data)
{
	if (data->first == NULL)
	{
		data->first = create_struct_arg(data);
		data->current = data->first;
	}
	else
	{
		data->current->next = create_struct_arg(data);
		data->current = data->current->next;
	}
	data->format_mod[data->format_pos] = '\0';
	data->move_in_arg = 1;
}

int		parse_and_move_format(t_data *data)
{
	set_ptr_chained_list_and_init(data);
	while (detect_pattern(data, \
		data->format[data->format_pos + data->move_in_arg]) == -1)
		data->move_in_arg++;
	if (data->format[data->format_pos + data->move_in_arg] == '\0')
		return (data->move_in_arg - 1);
	if (data->current->output_wide_length > 0)
		data->current->output_length += data->current->output_wide_length;
	else
		data->current->output_length += ft_strlen(data->current->output_arg);
	if (data->current->output_arg == NULL && data->error > 0 && \
		data->error != 100)
		data->current->output_arg = ft_strdup("");
	if (data->current->output_length < data->current->width)
	{
		data->current->width = \
			data->current->width - data->current->output_length;
		if (data->current->output_arg != NULL)
			get_output_malloc_width(data->current, data->current->output_arg[0]\
				, data->format[data->format_pos + data->move_in_arg]);
	}
	else
		data->current->width = 0;
	data->len_so_far += data->current->output_length + data->current->width;
	return (data->move_in_arg);
}
