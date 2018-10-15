/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:42:05 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/23 04:41:41 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int		nbword(const char *s, char c)
{
	int		in_word;
	int		count;

	in_word = 0;
	count = 0;
	while (*s != '\0')
	{
		if (in_word == 1 && *s == c)
			in_word = 0;
		if (in_word == 0 && *s != c)
		{
			in_word = 1;
			count++;
		}
		s++;
	}
	return (count);
}

static int		len_w(const char *s, char c)
{
	int				len;

	len = 0;
	while (*s != c && *s != '\0')
	{
		len++;
		s++;
	}
	return (len);
}

char			**ft_strsplit(char const *s, char c)
{
	char	**tab;
	int		nb_word;
	int		index;

	index = 0;
	nb_word = nbword((const char *)s, c);
	tab = (char **)mallocp(sizeof(*tab) * (nbword((const char *)s, c) + 1));
	if (!tab)
		return (NULL);
	while (nb_word--)
	{
		while (*s == c && *s != '\0')
			s++;
		tab[index] = ft_strsub((const char *)s, 0, len_w((const char *)s, c));
		if (!tab[index])
			return (NULL);
		s = s + len_w(s, c);
		index++;
	}
	tab[index] = NULL;
	return (tab);
}
