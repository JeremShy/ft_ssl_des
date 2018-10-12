#include <ft_ssl.h>


static void print_opt(t_opt *opt)
{
	if (opt->flags & I_OPT)
		printf("i_option : %s\n", opt->i_option);
	else
		printf("i_option : None\n");

	if (opt->flags & O_OPT)
		printf("o_option : %s\n", opt->o_option);
	else
		printf("o_option : None\n");
	if (opt->flags & K_OPT)
		printf("k_option : %s\n", opt->k_option);
	else
		printf("k_option : None\n");
	if (opt->flags & P_OPT)
		printf("p_option : %s\n", opt->p_option);
	else
		printf("p_option : None\n");
	if (opt->flags & S_OPT)
		printf("s_option : %s\n", opt->s_option);
	else
		printf("s_option : None\n");
	if (opt->flags & V_OPT)
		printf("v_option : %s\n", opt->v_option);
	else
		printf("v_option : None\n");
}

static int	compute_des(t_des *des, t_opt *opt)
{
		t_pbkdf2_params	params;

	ft_bzero(des, sizeof(t_des));
	if (opt->flags & K_OPT && opt->k_option)
	{
		if (!hex_string_to_bytes(opt->k_option, des->key, 8))
		{
			ft_putendl_fd("Error : Problem while parsing the key", 2);
			return (0);
		}
	}
	else if (opt->flags & P_OPT && opt->p_option)
	{
		if (getentropy(des->salt, 8) == -1)
		{
			ft_putendl_fd("Error while trying to generate a random salt.", 2);
			return (0);
		}
		params.password = (unsigned char *)opt->p_option;
		params.pass_len = ft_strlen(opt->p_option);
		params.salt = des->salt;
		params.salt_len = 8;
		params.iter = 10000;
		params.dklen = 8;
		params.out = (char*)des->key;
		pbkdf2_hmac_sha1(&params);
		des->salted = 1;
	}
	else
	{
		ft_putendl_fd("Error : You must specify at least a password or a key.", 2);
		return (0);
	}
	if (opt->flags & I_OPT)
	{
		if (!hex_string_to_bytes(opt->i_option, des->iv, 8))
		{
			ft_putendl_fd("Error : Problem while parsing the iv", 2);
			return (0);
		}
		// ft_putendl("iv :");
		// print_memory(des->iv, 8);
		des->ived = 1;
	}
	return (1);
}

int	main_des_ecb(t_opt *opt)
{
	t_des	des;
	char	*data;
	int		datalen;
	int		fd;

	printf("Called des_ecb\n");
	// print_opt(opt);

	if (!(compute_des(&des, opt)))
		return (0);
	if ((fd = open(opt->content, O_RDONLY)) == -1)
	{
		ft_putendl_fd("Error : Could not open the input file for reading", 2);
		return (0);
	}
	data = get_file(fd, &datalen);
	if (data == NULL)
	{
		ft_putendl_fd("Error: Read error.", 2);
		return (0);
	}
	des_encode(&des, (const uint8_t *)data, datalen, ecb);
	return (1);
}

int	main_des_cbc(t_opt *opt)
{
	t_des	des;

	if (!(compute_des(&des, opt)))
		return (0);
	if (!des.ived)
	{
		ft_putendl_fd("Error : An IV must be specified for the cbc mode to work.", 2);
		return (0);
	}
	return (1);
}