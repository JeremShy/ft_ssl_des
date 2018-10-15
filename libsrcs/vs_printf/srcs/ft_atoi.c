/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 20:49:48 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/22 20:50:18 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_atoi(const char *nptr)
{
	int	sign;
	int	result;

	sign = 0;
	result = 0;
	while (ft_isspace(*nptr) && *nptr)
		nptr++;
	if (*nptr == 43 || *nptr == 45)
	{
		if (*nptr == 45)
			sign = 1;
		nptr++;
	}
	while (ft_isdigit(*nptr) && *nptr)
	{
		result *= 10;
		result += (*nptr - 48);
		nptr++;
	}
	if (sign)
		return (-result);
	return (result);
}
