/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcamhi <jcamhi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/08 17:59:15 by jcamhi            #+#    #+#             */
/*   Updated: 2018/07/08 19:04:40 by jcamhi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include <libft.h>
# include <fcntl.h>
# include <unistd.h>
# include <math.h>
# include <stdio.h>

# define P_OPT	(1 << 0)
# define Q_OPT	(1 << 1)
# define R_OPT	(1 << 2)
# define S_OPT	(1 << 3)
# define D_OPT	(1 << 4)
# define E_OPT	(1 << 5)
# define I_OPT	(1 << 6)
# define O_OPT	(1 << 7)
# define K_OPT	(1 << 8)
# define V_OPT	(1 << 9)
# define A_OPT	(1 << 10)

/*
	** General
*/

typedef struct	s_opt
{
	int32_t		flags;
	char		*content;
	int			has_read_something;
	char		*i_option;
	char		*o_option;
	char		*k_option;
	char		*p_option;
	char		*s_option;
	char		*v_option;
}				t_opt;

int				padd_buffer(int original_file_size, int r, char *buffer);
uint32_t		rotl(uint32_t n, uint32_t x);
uint32_t		rotr(uint32_t n, uint32_t x);
void			print_result_32(uint buffer[4], t_opt *opt);

int				parse_options(int ac, char **av, t_opt *opt);

void			print_help(void);

void print_memory(char *start, size_t size);

/*
	** MD5
*/

typedef struct	s_params_md5
{
	uint		buffer[4];
	uint		k;
	uint		s;
	uint		i;
	uint		t[65];
	const uint	*x;
}				t_params_md5;

typedef uint	(*t_fghi) (uint, uint, uint);

int				read_file(char *filename, t_opt *opt);

void			stage1(t_params_md5 *params, char nbr_du_milieu[4][4]);
void			stage2(t_params_md5 *params, char nbr_du_milieu[4][4]);
void			stage3(t_params_md5 *params, char nbr_du_milieu[4][4]);
void			stage4(t_params_md5 *params, char nbr_du_milieu[4][4]);

void			compute_buffer(t_params_md5 *params, char nbr_du_milieu[4][4],
	void *buffer);
int				compute_from_string_md5(char *str, t_opt *opt);

uint			f_md5(uint b, uint c, uint d);
uint			g_md5(uint b, uint c, uint d);
uint			h_md5(uint b, uint c, uint d);
uint			i_md5(uint b, uint c, uint d);

uint			cshift(uint nbr, uint s);
uint			end_conv_32(uint nbr);

void			initialize_buffer(uint *buffer);
void			initialize_t(uint t[65]);

void			hash_buffer_md5(ssize_t r, t_params_md5 *params, char *buffer);
int				ft_init(t_params_md5 *params, size_t *original_file_size,
		int *fd, char *filename);

int				main_md5(t_opt *opt);

/*
	** SHA-256
*/

typedef struct	s_params_sha256
{
	uint32_t	*k;
	uint32_t	*h;
	uint32_t	*schedule;
	uint32_t	*working;
}				t_params_sha256;

int				main_256(t_opt *opt);
uint32_t		ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t		maj(uint32_t x, uint32_t y, uint32_t z);
uint32_t		gs0(uint32_t x);
uint32_t		gs1(uint32_t x);
uint32_t		ps0(uint32_t x);
uint32_t		ps1(uint32_t x);

void			sha256_compute_buffer(t_params_sha256 *params, void *buffer);
void			print_result_64(unsigned char buffer[32], t_opt *opt);
uint64_t		end_conv_64(uint64_t nbr);

int				sha256_padd_buffer(int original_file_size, int r, char *buffer);
void			init_constants_sha256(uint32_t k[64], uint32_t h[8],
				uint32_t schedule[64], uint32_t working[8]);

/*
	** Base64
*/

typedef struct	s_params_base64 {
	char alphabet[255];
}								t_params_base64;

int				main_base64(t_opt *opt);
void			base64_encode_from_fd(t_opt *opt, int fd, int output_fd);
void			base64_decode_from_fd(t_opt *opt, int fd, int output_fd);

/*
** sha1
*/

char	*sha1_encode(void *in, size_t len);

/*
** des
*/

int	main_des_ecb(t_opt *opt);
int	main_des_cbc(t_opt *opt);

#endif
