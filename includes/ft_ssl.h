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
# include <stdint.h>
# include <sys/mman.h>
# include <sys/random.h>

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

typedef struct	s_uint28
{
	uint32_t	x:28;
}				t_uint28;

typedef struct	s_uint48
{
	uint64_t	x:48;
}				t_uint48;

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
void				print_result_32(uint buffer[4], t_opt *opt);
char				*get_file(int fd, int *file_size);

int				parse_options(int ac, char **av, t_opt *opt);

void			print_help(void);

void print_memory(const void *start, size_t size);
char	*bytes_to_char(uint32_t *in, char *buffer, size_t in_size);
int	hex_string_to_bytes(const char *str, unsigned char *out, size_t size);

int8_t	permutate(const int8_t *in, int8_t *out, const int *permutation, size_t size);

/*
	** PBKDF2
*/

typedef struct	s_pbkdf2_params
{
	const unsigned char	*password;
	size_t	pass_len;

	const unsigned char	*salt;
	size_t	salt_len;

	int	iter;
	int dklen;

	char	*out;
}				t_pbkdf2_params;

int	pbkdf2_hmac_sha1(t_pbkdf2_params *params);

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

uint32_t	*sha1_encode(const void *in, size_t len);
int				main_sha1(t_opt *opt);

/*
** des
*/

typedef struct	s_des
{
	unsigned char	key[8];

	uint8_t				ived;
	unsigned char	iv[8];

	uint8_t				salted;
	unsigned char	salt[8];
}							t_des;

typedef enum e_mode
{
	ecb,
	cbc
}			t_mode;

extern const int	g_des_ip[];
extern const int	g_des_ip_inv[];
extern const int	g_des_e[];
extern const int	g_des_one[];
extern const int	g_des_two[];
extern const int	g_des_three[];
extern const int	g_des_four[];
extern const int	g_des_five[];
extern const int	g_des_six[];
extern const int	g_des_seven[];
extern const int	g_des_eight[];
extern const int	g_des_iteration_to_left_shift[];
extern const int	g_des_pc_one_left[];
extern const int	g_des_pc_one_right[];
extern const int	g_des_pc_two[];
extern const int	g_des_p[];
extern const int	g_des_lshift[];
extern const int	g_des_rotl_1[];
extern const int	g_des_rotl_2[];

int	main_des_ecb(t_opt *opt);
int	main_des_cbc(t_opt *opt);
void	print_block_as_char(uint64_t in);
// void	print_binary(uint8_t in);
void	print_binary(uint8_t *in, size_t size, size_t blocks);

void	compute_key_schedule(t_uint48 out[16], uint64_t key);

uint8_t	compute_s_box(uint8_t in, size_t i);

uint32_t	*des_encode(t_des *des, const uint8_t *data, size_t datalen, t_mode mode);
uint32_t rotl_28(uint32_t n, uint32_t x);


/*
** hmac
*/
int		main_hmac_sha1(t_opt *opt);
unsigned char	*hmac_sha1_encode(const void *str, int size, const unsigned char *key, size_t keylen);

#endif
