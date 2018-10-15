/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_qsortr_tab_int.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/03/30 19:53:28 by vsteffen          #+#    #+#             */
/*   Updated: 2016/04/10 20:19:25 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_qsortr_tab_int(int *array, int first, int last)
{
	int left;
	int right;
	int pivot;

	left = first - 1;
	right = last + 1;
	pivot = array[first];
	if (first >= last)
		return ;
	while (1)
	{
		right--;
		while (array[right] < pivot)
			right--;
		left++;
		while (array[left] > pivot)
			left++;
		if (left < right)
			ft_swap_int(&array[left], &array[right]);
		else
			break ;
	}
	ft_qsortr_tab_int(array, first, right);
	ft_qsortr_tab_int(array, right + 1, last);
}
