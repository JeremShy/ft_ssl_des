/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_main.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcamhi <jcamhi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/08 17:34:35 by jcamhi            #+#    #+#             */
/*   Updated: 2018/07/08 18:29:01 by jcamhi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <ft_ssl.h>

int	main_md5(t_opt *opt)
{
	if (opt->flags & S_OPT)
		compute_from_string_md5(opt->content, opt);
	else
		read_file(opt->content, opt);
	return (1);
}
