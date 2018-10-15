/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_d.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/05 19:46:53 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/05 21:59:50 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

static size_t	nb_numeral_d(intmax_t n)
{
	size_t count;

	count = 1;
	while (n /= 10)
		count++;
	return (count);
}

char			*ft_itoa_printflag(t_arg *arg, char *s, size_t len, intmax_t n)
{
	if (len - arg->flag_more > 0)
	{
		while (--len > 0)
			s[len] = '0';
		s[0] = '0';
	}
	if (arg->flag_more)
	{
		s[0] = '+';
		if (arg->flag_zero == 1)
			arg->flag_zero = 2;
	}
	if (n < 0)
	{
		s[0] = '-';
		if (arg->flag_zero == 1)
			arg->flag_zero = 2;
	}
	return (s);
}

char			*ft_itoa_printf(t_arg *arg, intmax_t n, size_t prec)
{
	size_t				len;
	char				*str;
	uintmax_t			tmp_nb;

	len = nb_numeral_d(n);
	if (len < prec)
		len = prec;
	tmp_nb = n;
	if (n < 0)
	{
		tmp_nb = -n;
		len++;
	}
	if (n >= 0 && arg->flag_more)
		len++;
	str = (char*)mallocp(sizeof(char) * len + 1);
	if (!str)
		return (NULL);
	str[len] = '\0';
	str[--len] = tmp_nb % 10 + '0';
	while (tmp_nb /= 10)
		str[--len] = tmp_nb % 10 + '0';
	return (ft_itoa_printflag(arg, str, len, n));
}

void			transform_d(t_arg *arg, intmax_t var_int_max)
{
	if (var_int_max == 0)
	{
		if (arg->precision == 0 && arg->flag_dot == 1)
			arg->output_arg = ft_strdup("");
		else
			arg->output_arg = malloc_prec_zero_doux(\
				arg->precision, arg, 'd');
	}
	else
		arg->output_arg = ft_itoa_printf(arg, var_int_max, arg->precision);
	if (arg->flag_space == 1 && arg->output_arg[0] != '+' \
		&& arg->output_arg[0] != '-')
		arg->output_arg = ft_strjoinaf2(" ", arg->output_arg);
}
