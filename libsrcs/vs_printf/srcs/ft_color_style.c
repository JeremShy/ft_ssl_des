/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_color_style.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/04/19 16:14:08 by vsteffen          #+#    #+#             */
/*   Updated: 2016/05/13 19:24:52 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_color_style(char *color1, char *color2, char *str, int again)
{
	if (color1)
		ft_putstr(color1);
	if (color2)
		ft_putstr(color2);
	if (str)
		ft_putstr(str);
	if (again == 0)
		ft_putstr(CS_RESET);
	else
		return ;
}
