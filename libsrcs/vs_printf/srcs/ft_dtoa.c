/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_dtoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/03/13 11:19:22 by vsteffen          #+#    #+#             */
/*   Updated: 2018/03/13 11:19:25 by vsteffen         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static uint8_t	ft_dtoa_zero_after_dot(double nb, uint8_t prec)
{
	uint8_t		zero_after_dot;
	uint8_t		tmp_prec;

	zero_after_dot = 0;
	tmp_prec = 0;
	while (++tmp_prec <= prec && \
		ft_d_extract_round_int_part(nb * (ft_pow_int64(10, tmp_prec))) == 0)
		zero_after_dot++;
	return (zero_after_dot);
}

static int8_t	ft_dtoa_add_zero(t_struct_fldo *fldo, char *output, \
	uint8_t *precision, uint8_t *pos_after_dot)
{
	uint8_t		zero_put;

	if (fldo->after_dot == 0)
	{
		*pos_after_dot = fldo->length_before_dot + fldo->dot;
		while ((*precision)-- > 0)
			output[(*pos_after_dot)++] = '0';
		output[*pos_after_dot] = '\0';
		return (1);
	}
	*pos_after_dot = fldo->length_before_dot + fldo->dot + \
		ft_length_numeral_int64(fldo->after_dot) + fldo->zero_after_dot;
	output[*pos_after_dot] = '\0';
	zero_put = 1;
	if (fldo->zero_after_dot)
		while (zero_put <= fldo->zero_after_dot && *precision > 0)
		{
			output[fldo->length_before_dot - 1 + fldo->dot + zero_put] = '0';
			zero_put++;
			(*precision)--;
		}
	if (*precision == 0)
		return (1);
	return (0);
}

static void		fill_array_for_dtoa(char *output, uint8_t precision, \
	t_struct_fldo *fldo)
{
	uint8_t		pos_after_dot;
	uint8_t		tmp_length_before_dot;

	tmp_length_before_dot = fldo->length_before_dot;
	output[tmp_length_before_dot] = '\0';
	output[--tmp_length_before_dot] = fldo->before_dot % 10 + '0';
	while (fldo->before_dot /= 10)
		output[--tmp_length_before_dot] = fldo->before_dot % 10 + '0';
	if (fldo->sign == 1)
		output[0] = fldo->sign_char;
	if (precision < 1)
		return ;
	output[fldo->length_before_dot] = '.';
	if (ft_dtoa_add_zero(fldo, output, &precision, &pos_after_dot))
		return ;
	output[--pos_after_dot] = fldo->after_dot % 10 + '0';
	while (fldo->after_dot /= 10)
	{
		if (precision == 0)
			break ;
		output[--pos_after_dot] = fldo->after_dot % 10 + '0';
		precision--;
	}
}

static void		ft_dtoa_sign(t_struct_fldo *fldo, double tmp_double, \
	uint8_t precision)
{
	if (fldo->before_dot < 0)
	{
		fldo->sign = 1;
		fldo->sign_char = '-';
		fldo->before_dot = -fldo->before_dot;
		tmp_double = -tmp_double;
		fldo->after_dot = ft_d_extract_round_int_part(\
			tmp_double * (ft_pow_int64(10, precision)));
	}
	else
		fldo->after_dot = ft_d_extract_round_int_part(\
			tmp_double * (ft_pow_int64(10, precision)));
}

char			*ft_dtoa(double nb, uint8_t precision)
{
	t_struct_fldo	fldo;
	char			*output;
	double			tmp_double;

	fldo.before_dot = (int64_t)nb;
	fldo.dot = 0;
	fldo.sign = 0;
	fldo.zero_after_dot = 0;
	if (precision == 0)
		fldo.before_dot = ft_d_extract_round_int_part(nb);
	else
		fldo.dot = 1;
	if (precision > 18)
		precision = 18;
	fldo.length_before_dot = ft_length_numeral_int64((int64_t)fldo.before_dot);
	tmp_double = nb - (double)fldo.before_dot;
	ft_dtoa_sign(&fldo, tmp_double, precision);
	if (fldo.dot)
		fldo.zero_after_dot = ft_dtoa_zero_after_dot(tmp_double, precision);
	if (fldo.sign)
		++fldo.length_before_dot;
	output = (char *)malloc(sizeof(char) * (fldo.length_before_dot + \
		fldo.dot + fldo.zero_after_dot + precision) + 1);
	fill_array_for_dtoa(output, precision, &fldo);
	return (output);
}
