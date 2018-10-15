/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_qsort_tab_str.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/04/10 20:13:03 by vsteffen          #+#    #+#             */
/*   Updated: 2016/04/10 20:21:36 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_qsort_tab_str(char **array, int first, int last)
{
	int		left;
	int		right;
	char	*pivot;

	left = first - 1;
	right = last + 1;
	pivot = array[first];
	if (first >= last)
		return ;
	while (1)
	{
		right--;
		while (ft_strcmp(array[right], pivot) > 0)
			right--;
		left++;
		while (ft_strcmp(array[left], pivot) < 0)
			left++;
		if (left < right)
			ft_swap_str(&array[left], &array[right]);
		else
			break ;
	}
	ft_qsort_tab_str(array, first, right);
	ft_qsort_tab_str(array, right + 1, last);
}
