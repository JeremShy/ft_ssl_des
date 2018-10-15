/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_pow_int64.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/15 19:25:34 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/15 22:28:25 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int64_t	ft_pow_int64(int64_t nb, uint8_t power)
{
	int64_t		result;
	uint8_t		count;

	count = 0;
	result = 1;
	while (count < power)
	{
		result *= nb;
		count++;
	}
	return (result);
}
