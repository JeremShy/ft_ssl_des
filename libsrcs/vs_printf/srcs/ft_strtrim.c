/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:43:48 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/23 04:35:57 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_isblanksp(int c)
{
	return ((c == 32 || c == 9 || c == 10) ? 1 : 0);
}

static int	ft_strnull(char *s)
{
	size_t len;

	len = ft_strlen(s);
	while (ft_isblanksp(*s))
	{
		len--;
		s++;
	}
	return ((!len) ? 1 : 0);
}

char		*ft_strtrim(char const *s)
{
	char const		*strbegin = s;
	unsigned int	first;
	unsigned int	last;

	first = 0;
	last = 0;
	if (!s)
		return (NULL);
	if (ft_strnull((char*)s))
		return (ft_strdup(""));
	while (*s && ft_isblanksp(*s))
	{
		first++;
		s++;
	}
	while (*s)
		s++;
	s--;
	while (*s && ft_isblanksp(*s))
	{
		last++;
		s--;
	}
	return (ft_strsub(strbegin, first, ft_strlen(strbegin) - first - last));
}
