/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:29:36 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:29:51 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	size_t	len_t;
	char	*str_null;

	if (s1 && s2)
	{
		len_t = ft_strlen(s1) + ft_strlen(s2);
		str_null = ft_strnew(len_t);
		if (str_null)
		{
			str_null = ft_strcpy(str_null, s1);
			str_null = ft_strcat(str_null, s2);
			return (str_null);
		}
	}
	return (NULL);
}
