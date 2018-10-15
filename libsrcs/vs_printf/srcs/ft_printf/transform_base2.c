/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_base2.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 16:55:26 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 16:55:28 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

uint8_t		count_numeral_base(uintmax_t nb, uint8_t base)
{
	uint8_t		count;

	count = 1;
	while (nb /= base)
		++count;
	return (count);
}

char		*ft_itoa_base_printf(uintmax_t nb, uint8_t base, char *alph, \
	size_t prec)
{
	char		*output;
	size_t		length;

	if (nb == 0)
		return (ft_strdup("0"));
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
