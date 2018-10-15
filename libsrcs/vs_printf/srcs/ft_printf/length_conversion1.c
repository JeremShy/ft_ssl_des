/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   length_conversion1.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/01 19:35:47 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/01 19:35:51 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf.h"

void	detect_length_mod_hh2(t_data *data, char conversion)
{
	if (conversion == 'U')
		transform_u(data->current, (unsigned long int)va_arg(data->ap, \
			unsigned long int));
	else if (conversion == 'n')
		transform_n(data, (intmax_t *)va_arg(data->ap, signed char *));
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

void	detect_length_mod_hh1(t_data *data, char conversion)
{
	if (conversion == 'd' || conversion == 'i')
		transform_d(data->current, (signed char)va_arg(data->ap, int));
	else if (conversion == 'o')
		transform_o(data->current, (unsigned char)va_arg(data->ap, int));
	else if (conversion == 'u')
		transform_u(data->current, (unsigned char)va_arg(data->ap, int));
	else if (conversion == 'x')
		transform_x(data->current, (unsigned char)va_arg(data->ap, int));
	else if (conversion == 'X')
		transform_big_x(data->current, (unsigned char)va_arg(data->ap, int));
	else if (conversion == 'D')
		transform_d(data->current, (long int)va_arg(data->ap, long int));
	else if (conversion == 'O')
		transform_o(data->current, (unsigned long int)va_arg(data->ap, \
			unsigned long int));
	else
		detect_length_mod_hh2(data, conversion);
}

void	detect_length_mod_h2(t_data *data, char conversion)
{
	if (conversion == 'U')
		transform_u(data->current, (unsigned long int)va_arg(data->ap, \
			unsigned long int));
	else if (conversion == 'n')
		transform_n(data, (intmax_t *)va_arg(data->ap, short *));
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

void	detect_length_mod_h1(t_data *data, char conversion)
{
	if (conversion == 'd' || conversion == 'i')
		transform_d(data->current, (short)va_arg(data->ap, int));
	else if (conversion == 'o')
		transform_o(data->current, (unsigned short)va_arg(data->ap, int));
	else if (conversion == 'u')
		transform_u(data->current, (unsigned short)va_arg(data->ap, int));
	else if (conversion == 'x')
		transform_x(data->current, (unsigned short)va_arg(data->ap, int));
	else if (conversion == 'X')
		transform_big_x(data->current, (unsigned short)va_arg(data->ap, int));
	else if (conversion == 'D')
		transform_d(data->current, (long int)va_arg(data->ap, long int));
	else if (conversion == 'O')
		transform_o(data->current, (unsigned long int)va_arg(data->ap, \
			unsigned long int));
	else
		detect_length_mod_h2(data, conversion);
}
