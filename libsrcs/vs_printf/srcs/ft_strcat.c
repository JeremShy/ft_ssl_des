/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcat.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:16:05 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:16:49 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strcat(char *dest, const char *src)
{
	size_t pos;
	size_t len;

	len = ft_strlen(dest);
	pos = 0;
	while (src[pos])
	{
		dest[len + pos] = src[pos];
		pos++;
	}
	dest[len + pos] = '\0';
	return (dest);
}
