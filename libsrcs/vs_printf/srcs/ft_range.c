/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_range.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/04 19:07:34 by vsteffen          #+#    #+#             */
/*   Updated: 2016/11/22 16:01:06 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		*ft_range(int min, int max)
{
	int		*ret;
	int		i;

	if (min >= max)
		return (NULL);
	ret = (int *)malloc(sizeof(int) * (max - min));
	i = 0;
	while (min < max)
	{
		ret[i] = min;
		min++;
		i++;
	}
	return (ret);
}
