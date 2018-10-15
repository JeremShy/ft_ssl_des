/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 21:18:38 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 23:50:17 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dest, const void *src, int c, size_t n)
{
	char		*tmp_dest;
	const char	*tmp_src = src;

	if (!dest || !src)
		return (NULL);
	tmp_dest = dest;
	while (n--)
	{
		*tmp_dest++ = *tmp_src;
		if (*tmp_src == c)
			return (tmp_dest);
		tmp_src++;
	}
	return (NULL);
}
