/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_iterative_factorial.c                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 14:46:24 by vsteffen          #+#    #+#             */
/*   Updated: 2016/11/22 15:58:06 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_iterative_factorial(int nb)
{
	int		ret;

	ret = 1;
	if (nb < 0 || nb > 12)
		return (0);
	while (nb > 0)
	{
		ret *= nb;
		nb--;
	}
	return (ret);
}
