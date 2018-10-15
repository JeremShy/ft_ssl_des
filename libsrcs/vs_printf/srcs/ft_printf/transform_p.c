/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_p.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/05 22:48:14 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/05 22:50:07 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

char				*ft_ptoa_base_printf(uintptr_t nb, uint8_t base, \
	char *alph, size_t prec)
{
	char		*output;
	size_t		length;

	length = (size_t)count_numeral_base(nb, base);
	if (length < prec)
		length = prec;
	output = (char *)mallocp(sizeof(char) * length + 1);
	output[length] = '\0';
	while (nb != 0)
	{
		length--;
		output[length] = alph[nb % base];
		nb /= base;
	}
	if (length > 0)
	{
		while (--length > 0)
			output[length] = '0';
		output[0] = '0';
	}
	return (output);
}

void				transform_p(t_arg *arg, void *ptr)
{
	uintptr_t	uip;

	uip = (uintptr_t)ptr;
	if (uip == 0)
	{
		if (arg->precision == 0 && arg->flag_dot == 1)
			arg->output_arg = ft_strdup("");
		else
			arg->output_arg = malloc_prec_zero_doux(arg->precision, arg, 'd');
	}
	else
		arg->output_arg = ft_ptoa_base_printf(uip, 16, "0123456789abcdef", \
			arg->precision);
	arg->output_arg = ft_strjoinaf2("0x", arg->output_arg);
}
