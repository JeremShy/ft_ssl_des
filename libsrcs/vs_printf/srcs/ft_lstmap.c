/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <vsteffen@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/12/22 21:28:34 by vsteffen          #+#    #+#             */
/*   Updated: 2015/12/23 00:38:52 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list*start;
	t_list*new;
	t_list*tmp;

	if (!lst)
		return (NULL);
	tmp = NULL;
	start = NULL;
	while (lst)
	{
		new = f(ft_lstnew(lst->content, lst->content_size));
		if (!start)
			start = new;
		tmp = ft_lstpcontent(&tmp, new);
		lst = lst->next;
	}
	return (start);
}
