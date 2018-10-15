/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:21:38 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:22:12 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strcpy(char *dest, const char *src)
{
	unsigned long	pos;

	if (dest && src)
	{
		pos = 0;
		while (src[pos] != '\0')
		{
			dest[pos] = src[pos];
			pos++;
		}
		dest[pos] = src[pos];
	}
	return (dest);
}
