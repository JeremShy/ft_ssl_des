/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 21:20:48 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 21:20:57 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	const unsigned char *tmp_s = s;

	while (n--)
	{
		if (*tmp_s == (unsigned char)c)
			return ((void*)tmp_s);
		tmp_s++;
	}
	return (NULL);
}
