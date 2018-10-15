/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:36:25 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 23:55:18 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncpy(char *dest, const char *src, size_t n)
{
	size_t pos;

	pos = 0;
	while (pos < n && src[pos])
	{
		dest[pos] = src[pos];
		pos++;
	}
	while (pos < n)
		dest[pos++] = '\0';
	return (dest);
}
