/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_dtoa_clean.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/13 13:22:48 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/13 13:22:51 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_dtoa_clean_cut_string(char *output, size_t last_zero, size_t pos_dot)
{
	if (pos_dot + 1 == last_zero)
		output[last_zero + 1] = '\0';
	else
		output[last_zero] = '\0';
}

char	*ft_dtoa_clean(double nb, uint8_t precision)
{
	char	*output;
	size_t	pos;
	size_t	last_zero;
	size_t	pos_dot;
	int8_t	flag_dot;

	output = ft_dtoa(nb, precision);
	pos = ft_strlen(output);
	last_zero = pos;
	flag_dot = 0;
	while (pos > 0 && !flag_dot)
	{
		if (output[pos - 1] == '0')
			last_zero = pos - 1;
		if (output[pos - 1] == '.')
		{
			pos_dot = pos - 1;
			flag_dot = 1;
		}
		pos--;
	}
	if (!flag_dot)
		return (output);
	ft_dtoa_clean_cut_string(output, last_zero, pos_dot);
	return (output);
}
