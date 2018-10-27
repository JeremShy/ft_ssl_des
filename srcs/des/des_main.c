#include <ft_ssl.h>
#include <sys/stat.h>


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
	printf("content : %s\n", opt->content);
}

static int	compute_des(t_des *des, t_opt *opt, int *in_fd)
{
	t_btk_md5_params	params;
	char	buf[8];
	struct stat	s_buf;

	ft_bzero(des, sizeof(t_des));
	if (opt->flags & V_OPT)
	{
		if (!opt->v_option || !hex_string_to_bytes(opt->v_option, des->iv, 8))
		{
			ft_putendl_fd("Error : Problem while parsing the iv", 2);
			return (0);
		}
		des->ived = 1;
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

	if (opt->flags & I_OPT)
	{
		if (!opt->i_option)
		{
			if (des->out_fd != 1)
				close(des->out_fd);
			ft_putendl_fd("Error !\n", 2);
			return (0);
		}
		if ((*in_fd = open(opt->i_option, O_RDONLY)) == -1)
		{
			if (des->out_fd != 1)
				close(des->out_fd);
			ft_putendl_fd("Error while trying to open file for reading.", 2);
			return (0);
		}
		if (fstat(*in_fd, &s_buf) == -1 || !(S_ISREG(s_buf.st_mode)))
		{
			if (des->out_fd != 1)
				close(des->out_fd);
			ft_putendl_fd("Can't stat input file, or the input file is a folder.", 2);
			return (0);
		}
	}
	else
		*in_fd = 0;

	if (opt->flags & K_OPT && opt->k_option)
	{
		if (!hex_string_to_bytes(opt->k_option, des->key, 8))
		{
			ft_putendl_fd("Error : Problem while parsing the key", 2);
			return (0);
		}
	}
	else
	{
		if (!(opt->flags & P_OPT) || !opt->p_option)
		{
			opt->flags &= P_OPT;
			opt->p_option = ft_strdup(getpass("Please enter a password :"));
		}
		if (des->encode == 1)
		{
			if (getentropy(des->salt, 8) == -1)
			{
				ft_putendl_fd("Error while trying to generate a random salt.", 2);
				return (0);
			}
		}
		else
		{
			if (read(*in_fd, buf, 8) != 8)
				return (0);
			if (ft_strncmp(buf, "Salted__", 8))
			{
				return (0);
			}
			if (read(*in_fd, des->salt, 8) != 8)
				return (0);
		}
		params.salt = des->salt;
		// printf("salt : \n");
		// print_memory(params.salt, 8);
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
		des->salted = 1;
		des->ived = 1;
	}
	if (opt->flags & O_OPT)
	{
		if (!opt->o_option)
		{
			ft_putendl_fd("Error : Syntax error on -o option", 2);
			return (0);
		}
		if ((des->out_fd = open(opt->o_option, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1)
		{
			ft_putendl_fd("Error : Could not open output file for writing\n", 2);
			return (0);
		}
	}
	else
		des->out_fd = 1;

	return (1);
}

int	main_des_ecb(t_opt *opt)
{
	t_des	des;
	char	*data;
	int		datalen;
	int		fd;

	if (!(compute_des(&des, opt, &fd)))
		return (0);
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

// TODO close out_fd and fd everywhere if needed
int	main_des_cbc(t_opt *opt)
{
	t_des	des;
	char	*data;
	int		datalen;
	int		fd;
	int		out_fd;

	// print_opt(opt);
	if (!(compute_des(&des, opt, &fd)))
		return (0);
	if (!des.ived)
	{
		ft_putendl_fd("Error : An IV must be specified for the cbc mode to work.", 2);
		return (0);
	}
	data = get_file(fd, &datalen);
	if (data == NULL)
	{
		ft_putendl_fd("Error: Read error.", 2);
		return (0);
	}
	des_encode(&des, (const uint8_t *)data, datalen, cbc);
	if (des.out_fd != 0)
		close(des.out_fd);
	free(data);
	return (1);
}
