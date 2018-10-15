/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_rounded.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/03/25 16:52:20 by vsteffen          #+#    #+#             */
/*   Updated: 2016/03/25 16:54:09 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

float	ft_rounded(float number, int decimal)
{
	return (number >= 0) ? ((int)(number * decimal + 0.5) / (decimal * 1.0))
	: ((int)(number * decimal - 0.5) / (decimal * 1.0));
}
