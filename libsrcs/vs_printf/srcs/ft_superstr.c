/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_superstr.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/05/15 16:05:26 by vsteffen          #+#    #+#             */
/*   Updated: 2016/05/15 16:07:43 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_superstr(char *str1, char *str2, char *str3, char *str4)
{
	if (str1)
		ft_putstr(str1);
	if (str2)
		ft_putstr(str2);
	if (str3)
		ft_putstr(str3);
	if (str4)
		ft_putstr(str4);
}
