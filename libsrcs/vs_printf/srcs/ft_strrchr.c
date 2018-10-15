/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:40:37 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 23:57:35 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	char *last_pattern;

	last_pattern = NULL;
	if (!s)
		return (NULL);
	while (*s)
	{
		if (*s == (char)c)
			last_pattern = (char *)s;
		s++;
	}
	if (!*s && *s == (char)c)
		last_pattern = (char *)s;
	return ((last_pattern) ? last_pattern : NULL);
}
