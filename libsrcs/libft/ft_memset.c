/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcamhi <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/23 11:41:27 by jcamhi            #+#    #+#             */
/*   Updated: 2015/11/25 16:12:59 by jcamhi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>

void	*ft_memset(void *b, int c, size_t len)
{
	size_t			i;
	unsigned char	*current;

	i = 0;
	while (i < len)
	{
		current = b + i;
		*current = (unsigned char)c;
		i++;
	}
	return (b);
}
