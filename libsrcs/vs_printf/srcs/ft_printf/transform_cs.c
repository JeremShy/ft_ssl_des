/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_cs.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 17:47:06 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 17:47:09 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

char	*ft_strdup_mod_prec(const char *s, size_t prec, int8_t flag_asterisk)
{
	size_t		pos;
	char		*dest;

	pos = 0;
	dest = (char*)mallocp(sizeof(char) * prec + 1);
	while (s[pos] && (flag_asterisk == 1 || prec > pos))
	{
		dest[pos] = s[pos];
		pos++;
	}
	dest[pos] = '\0';
	return (dest);
}

void	transform_c(t_arg *arg, char var_char)
{
	char		*output;

	output = (char*)malloc(sizeof(char) * 2);
	output[0] = var_char;
	output[1] = '\0';
	arg->output_arg = output;
	if (var_char == '\0')
		arg->output_length++;
}

void	transform_s(t_arg *arg, char *var_string)
{
	if (var_string == NULL)
	{
		if (arg->flag_dot == 1)
			arg->output_arg = ft_strdup_mod_prec(\
				"(null)", arg->precision, arg->flag_asterisk);
		else
			arg->output_arg = ft_strdup("(null)");
	}
	else
	{
		if (arg->flag_dot == 1)
			arg->output_arg = ft_strdup_mod_prec(\
				var_string, arg->precision, arg->flag_asterisk);
		else
			arg->output_arg = ft_strdup(var_string);
	}
}
