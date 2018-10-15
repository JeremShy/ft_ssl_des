/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_length_numeral_int64.c                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/15 19:23:24 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/15 19:25:10 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

uint8_t	ft_length_numeral_int64(int64_t nb)
{
	uint8_t		count;

	count = 1;
	while (nb /= 10)
		++count;
	return (count);
}
