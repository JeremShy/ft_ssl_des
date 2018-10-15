/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:30:40 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:30:46 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dest, const char *src, size_t size)
{
	size_t len_dest;
	size_t len_src;
	size_t size_beginning;

	size_beginning = size;
	len_dest = ft_strlen(dest);
	len_src = ft_strlen(src);
	while (*dest && size)
	{
		dest++;
		size--;
	}
	if (!size)
		return (size_beginning + len_src);
	while (*src && size-- > 1)
		*dest++ = *src++;
	*dest = '\0';
	return (len_dest + len_src);
}
