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
	// t_pbkdf2_params	params;
	t_btk_md5_params	params;

	ft_bzero(des, sizeof(t_des));
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
	if (opt->flags & K_OPT && opt->k_option)
	{
		if (!hex_string_to_bytes(opt->k_option, des->key, 8))
		{
			ft_putendl_fd("Error : Problem while parsing the key", 2);
			printf("key : %s\n", opt->k_option);
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
		params.salt = des->salt;
		params.data = (void*)opt->p_option;
		params.data_len = ft_strlen(opt->p_option);
		params.key = des->key;
		params.key_len = 8;
		params.iv = des->iv;
		if (des->ived == 0)
			params.iv_len = 8;
		else
			params.iv_len = 0;
		if (!bytes_to_key_md5(&params))
		{
			ft_putendl_fd("Error while trying to generate a key from the password.", 2);
		}
		// printf("Salt : \n");
		// print_memory(params.salt, 8);
		// printf("Key : \n");
		// print_memory(des->key, 8);
		// printf("Iv : \n");
		// print_memory(des->iv, 8);
		des->salted = 1;
		des->ived = 1;
	}
	else
	{
		ft_putendl_fd("Error : You must specify at least a password or a key.", 2);
		return (0);
	}
	if (opt->flags & E_OPT && opt->flags & S_OPT)
	{
		ft_putendl_fd("Error : You must only specify one of -e or -d", 2);
		return (0);
	}
	if (opt->flags & E_OPT)
		des->encode = 1;
	else if (opt->flags & D_OPT)
		des->encode = 0;
	else
	{
		ft_putendl_fd("Error : You must specify one of -e or -d", 2);
		return (0);
	}

	return (1);
}

int	main_des_ecb(t_opt *opt)
{
	t_des	des;
	char	*data;
	int		datalen;
	int		fd;

	// printf("Called des_ecb\n");
	// print_opt(opt);

	if (!(compute_des(&des, opt)))
		return (0);
	if (!opt->content)
		fd = 0;
	else if ((fd = open(opt->content, O_RDONLY)) == -1)
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
	free(data);
	return (1);
}

int	main_des_cbc(t_opt *opt)
{
	t_des	des;
	char	*data;
	int		datalen;
	int		fd;

	if (!(compute_des(&des, opt)))
		return (0);
	if (!des.ived)
	{
		ft_putendl_fd("Error : An IV must be specified for the cbc mode to work.", 2);
		return (0);
	}
	if (!opt->content)
		fd = 0;
	else if ((fd = open(opt->content, O_RDONLY)) == -1)
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
	des_encode(&des, (const uint8_t *)data, datalen, cbc);
	free(data);
	return (1);
}
