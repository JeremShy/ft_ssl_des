/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsub.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:43:15 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/23 04:20:47 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include "libft.h"

char	*ft_strsub(char const *s, unsigned int start, size_t len)
{
	char	*str;
	size_t	pos;

	if (s == NULL)
		return (NULL);
	str = (char*)mallocp(sizeof(char) * (len + 1));
	if (str == NULL)
		return (NULL);
	pos = 0;
	while (pos < len && s[start] != '\0')
	{
		str[pos] = s[start];
		start++;
		pos++;
	}
	str[pos] = '\0';
	return (str);
}
