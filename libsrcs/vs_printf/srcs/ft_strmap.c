/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:32:12 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:32:20 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmap(char const *s, char (*f)(char))
{
	int		i;
	char	*mapstr;

	if (!s || !f)
		return (NULL);
	mapstr = (char*)mallocp(sizeof(char) * (ft_strlen(s) + 1));
	if (!mapstr)
		return (NULL);
	i = -1;
	while (s[++i])
		mapstr[i] = f(s[i]);
	mapstr[i] = '\0';
	return (mapstr);
}
