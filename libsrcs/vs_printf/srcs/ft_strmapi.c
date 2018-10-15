/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:33:09 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:33:51 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmapi(char const *s, char (*f)(unsigned int, char))
{
	unsigned int	pos;
	char			*mapstr;

	if (!s || !f)
		return (NULL);
	mapstr = (char*)mallocp(sizeof(char) * (ft_strlen(s) + 1));
	if (!mapstr)
		return (NULL);
	pos = -1;
	while (s[++pos])
		mapstr[pos] = f(pos, s[pos]);
	mapstr[pos] = '\0';
	return (mapstr);
}
