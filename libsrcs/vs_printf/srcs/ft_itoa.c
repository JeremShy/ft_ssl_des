/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 21:05:55 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/23 04:09:20 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static size_t	nb_numeral(int n)
{
	size_t count;

	count = 1;
	while (n /= 10)
		count++;
	return (count);
}

char			*ft_itoa(int n)
{
	size_t				len;
	char				*str;
	unsigned int		tmp_nb;

	len = nb_numeral(n);
	tmp_nb = n;
	if (n < 0)
	{
		tmp_nb = -n;
		len++;
	}
	str = (char*)mallocp(sizeof(char) * len + 1);
	if (!str)
		return (NULL);
	str[len] = 0;
	str[--len] = tmp_nb % 10 + '0';
	while (tmp_nb /= 10)
		str[--len] = tmp_nb % 10 + '0';
	if (n < 0)
		str[0] = '-';
	return (str);
}
