/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcamhi <jcamhi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/08 17:33:55 by jcamhi            #+#    #+#             */
/*   Updated: 2018/07/08 17:33:55 by jcamhi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <ft_ssl.h>

uint	cshift(uint nbr, uint s)
{
	return (uint)(((nbr) << (s)) |
		(((nbr) & ((-1u) << (32 - (s)))) >> (32 - (s))));
}

void	print_help(void)
{
	ft_putstr_fd("\nStandard commands\n\n", 2);
	ft_putstr_fd("Message Digest commands\nmd5\tsha1\tsha256\tsha512\n\n", 2);
	ft_putstr_fd("Cipher commands\nbase64\tdes\tdes-cbc\tdes-ecb\n\n", 2);
}

void	compute_buffer(t_params_md5 *params, char nbr_du_milieu[4][4],
	void *buffer)
{
	uint	buffer_save[4];

	params->x = buffer;
	ft_memcpy(buffer_save, params->buffer, sizeof(params->buffer));
	stage1(params, nbr_du_milieu);
	stage2(params, nbr_du_milieu);
	stage3(params, nbr_du_milieu);
	stage4(params, nbr_du_milieu);
	params->buffer[0] = (uint)params->buffer[0] + (uint)buffer_save[0];
	params->buffer[1] = (uint)params->buffer[1] + (uint)buffer_save[1];
	params->buffer[2] = (uint)params->buffer[2] + (uint)buffer_save[2];
	params->buffer[3] = (uint)params->buffer[3] + (uint)buffer_save[3];
}

int		main(int argc, char **argv)
{
	t_opt	opt;

	if (argc == 1)
	{
		ft_putstr_fd("Usage : not like this\n", 2);
		return (1);
	}

	char	out[21];
	t_pbkdf2_params params = {(unsigned char *)"passwordPASSWORDpassword", 25, (unsigned char *)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, 25, out};
	return pbkdf2_hmac_sha1(&params);

	if (!parse_options(argc, argv, &opt))
		return (2);
	return (88);
}
