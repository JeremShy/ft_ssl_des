/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strequ.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 22:26:27 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 22:26:34 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_strequ(char const *s1, char const *s2)
{
	int		pos;

	pos = 0;
	if (!s1 || !s2)
		return (0);
	if (s1[pos] == '\0' && s2[pos] == '\0')
		return (1);
	while (s1[pos] || s2[pos])
	{
		if (s1[pos] != s2[pos])
			return (0);
		pos++;
	}
	return (1);
}
