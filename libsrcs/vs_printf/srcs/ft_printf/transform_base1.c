/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   transform_base1.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/06 16:55:05 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/06 16:55:22 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void				transform_o_flag_hash(t_arg *arg, uintmax_t var_uintmax)
{
	if (var_uintmax == 0)
	{
		if (arg->flag_dot == 1 && arg->precision > 0)
			arg->output_arg = malloc_prec_zero_doux(arg->precision, arg, \
				'o');
		else
			arg->output_arg = ft_strdup("0");
	}
	else if (arg->flag_dot == 1)
	{
		arg->output_arg = ft_itoa_base_printf(var_uintmax, 8, \
			"0123456789abcdef", arg->precision);
		if (arg->precision == 0)
			arg->output_arg = ft_strjoinaf2("0", arg->output_arg);
	}
	else
	{
		arg->output_arg = ft_itoa_base_printf(var_uintmax, 8, \
			"0123456789abcdef", arg->precision);
		arg->output_arg = ft_strjoinaf2("0", arg->output_arg);
	}
}

void				transform_o(t_arg *arg, uintmax_t var_uintmax)
{
	if (arg->flag_hash == 1)
	{
		transform_o_flag_hash(arg, var_uintmax);
		return ;
	}
	else if (var_uintmax == 0)
	{
		if (arg->precision == 0 && arg->flag_dot == 1)
			arg->output_arg = ft_strdup("");
		else
			arg->output_arg = malloc_prec_zero_doux(arg->precision, arg, 'o');
		return ;
	}
	else
		arg->output_arg = ft_itoa_base_printf(var_uintmax, 8, \
			"0123456789abcdef", arg->precision);
}

void				transform_u(t_arg *arg, uintmax_t var_uintmax)
{
	if (var_uintmax == 0)
	{
		if (arg->precision == 0 && arg->flag_dot == 1)
			arg->output_arg = ft_strdup("");
		else
			arg->output_arg = malloc_prec_zero_doux(arg->precision, arg, 'u');
	}
	else
		arg->output_arg = ft_itoa_base_printf(var_uintmax, 10, \
			"0123456789abcdef", arg->precision);
}

void				transform_x(t_arg *arg, uintmax_t var_uintmax)
{
	if (var_uintmax == 0)
	{
		if (arg->precision == 0 && arg->flag_dot == 1)
			arg->output_arg = ft_strdup("");
		else
			arg->output_arg = malloc_prec_zero_doux(arg->precision, arg, 'x');
	}
	else
		arg->output_arg = ft_itoa_base_printf(var_uintmax, 16, \
			"0123456789abcdef", arg->precision);
	if (arg->flag_hash && var_uintmax > 0)
	{
		arg->output_arg = ft_strjoinaf2("0x", arg->output_arg);
	}
}

void				transform_big_x(t_arg *arg, uintmax_t var_uintmax)
{
	if (var_uintmax == 0)
	{
		if (arg->precision == 0 && arg->flag_dot == 1)
			arg->output_arg = ft_strdup("");
		else
			arg->output_arg = malloc_prec_zero_doux(arg->precision, arg, 'X');
	}
	else
		arg->output_arg = ft_itoa_base_printf(var_uintmax, 16, \
			"0123456789ABCDEF", arg->precision);
	if (arg->flag_hash && var_uintmax > 0)
	{
		arg->output_arg = ft_strjoinaf2("0X", arg->output_arg);
	}
}
