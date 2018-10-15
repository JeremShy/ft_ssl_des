/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_f2.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/05 22:26:45 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/05 22:26:48 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

int64_t			ft_d_extract_round_int_part_printf(double nb)
{
	return (nb >= 0 ? (int64_t)(nb + 0.5) : (int64_t)(nb - 0.5));
}

void			transform_f(t_arg *arg, double var_float)
{
	arg->output_arg = ft_dtoa_printf(arg, var_float, arg->precision);
	if (arg->flag_space == 1 && arg->output_arg[0] != '+' \
		&& arg->output_arg[0] != '-')
		arg->output_arg = ft_strjoinaf2(" ", arg->output_arg);
}
