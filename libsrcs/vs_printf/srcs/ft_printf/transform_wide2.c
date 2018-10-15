/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_wide2.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 17:58:45 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 17:58:46 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int8_t	get_wchar2(wchar_t wide, char *output, size_t output_pos)
{
	if (wide <= 0xFFFF)
	{
		output[output_pos] = (wide >> 12) | 0xE0;
		output[output_pos + 1] = ((wide >> 6) | 0x80) & 0xBF;
		output[output_pos + 2] = (wide | 0x80) & 0xBF;
		output[output_pos + 3] = 0;
		return (3);
	}
	else if (wide <= 0x10FFFF)
	{
		output[output_pos] = (wide >> 18) | 0xF0;
		output[output_pos + 1] = ((wide >> 12) | 0x80) & 0xBF;
		output[output_pos + 2] = ((wide >> 6) | 0x80) & 0xBF;
		output[output_pos + 3] = (wide | 0x80) & 0xBF;
		return (4);
	}
	return (0);
}

int8_t	get_wchar1(wchar_t wide, char *output, size_t output_pos)
{
	if (wide <= 0x7F)
	{
		output[output_pos] = wide & 0x7F;
		output[output_pos + 1] = 0;
		output[output_pos + 2] = 0;
		output[output_pos + 3] = 0;
		return (1);
	}
	else if (wide <= 0x7FF)
	{
		output[output_pos] = (wide >> 6) | 0xC0;
		output[output_pos + 1] = ((wide & 0x3F) | 0x80) & 0xBF;
		output[output_pos + 2] = 0;
		output[output_pos + 3] = 0;
		return (2);
	}
	else
		return (get_wchar2(wide, output, output_pos));
}

void	transform_wide_c(t_data *data, t_arg *arg, wchar_t wide)
{
	char		*output;

	output = (char *)malloc(sizeof(char) * 4 + 1);
	if ((arg->output_wide_length += get_wchar1(wide, output, 0)) == 0)
	{
		data->error = 1;
		return ;
	}
	output[arg->output_wide_length] = '\0';
	arg->output_arg = output;
}
