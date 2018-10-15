/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   length_conversion3.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/01 18:11:26 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/01 19:38:50 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	detect_length_mod_j2(t_data *data, char conversion)
{
	if (conversion == 'O')
		transform_o(data->current, \
			(unsigned long int)va_arg(data->ap, uintmax_t));
	else if (conversion == 'U')
		transform_u(data->current, \
			(unsigned long int)va_arg(data->ap, uintmax_t));
	else if (conversion == 'n')
		transform_n(data, (intmax_t *)va_arg(data->ap, intmax_t *));
	else if (conversion == 'p')
		transform_p(data->current, va_arg(data->ap, void *));
	else if (conversion == 'C')
		transform_wide_c(data, data->current, \
			(wchar_t)va_arg(data->ap, wint_t));
	else if (conversion == 'S')
		transform_wide_s(data, data->current, va_arg(data->ap, wchar_t *));
	else
		data->error = 1;
}

void	detect_length_mod_j1(t_data *data, char conversion)
{
	if (conversion == 'd' || conversion == 'i')
		transform_d(data->current, (intmax_t)va_arg(data->ap, intmax_t));
	else if (conversion == 'o')
		transform_o(data->current, (uintmax_t)va_arg(data->ap, uintmax_t));
	else if (conversion == 'u')
		transform_u(data->current, (uintmax_t)va_arg(data->ap, uintmax_t));
	else if (conversion == 'x')
		transform_x(data->current, (uintmax_t)va_arg(data->ap, uintmax_t));
	else if (conversion == 'X')
		transform_big_x(data->current, (uintmax_t)va_arg(data->ap, uintmax_t));
	else if (conversion == 'D')
		transform_d(data->current, (long int)va_arg(data->ap, intmax_t));
	else
		detect_length_mod_j2(data, conversion);
}

void	detect_length_mod_z2(t_data *data, char conversion)
{
	if (conversion == 'O')
		transform_o(data->current, (unsigned long int)va_arg(data->ap, size_t));
	else if (conversion == 'U')
		transform_u(data->current, (unsigned long int)va_arg(data->ap, size_t));
	else if (conversion == 'n')
		transform_n(data, (intmax_t *)va_arg(data->ap, intmax_t *));
	else if (conversion == 'p')
		transform_p(data->current, va_arg(data->ap, void *));
	else if (conversion == 'C')
		transform_wide_c(data, data->current, \
			(wchar_t)va_arg(data->ap, wint_t));
	else if (conversion == 'S')
		transform_wide_s(data, data->current, va_arg(data->ap, wchar_t *));
	else
		data->error = 1;
}

void	detect_length_mod_z1(t_data *data, char conversion)
{
	if (conversion == 'd' || conversion == 'i')
		transform_d(data->current, (intmax_t)va_arg(data->ap, intmax_t));
	else if (conversion == 'o')
		transform_o(data->current, (size_t)va_arg(data->ap, size_t));
	else if (conversion == 'u')
		transform_u(data->current, (size_t)va_arg(data->ap, size_t));
	else if (conversion == 'x')
		transform_x(data->current, (size_t)va_arg(data->ap, size_t));
	else if (conversion == 'X')
		transform_big_x(data->current, (size_t)va_arg(data->ap, size_t));
	else if (conversion == 'D')
		transform_d(data->current, (long int)va_arg(data->ap, intmax_t));
	else
		detect_length_mod_z2(data, conversion);
}
