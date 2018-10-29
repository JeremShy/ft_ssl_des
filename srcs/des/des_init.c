#include <ft_ssl.h>
#include <sys/stat.h>

int	handle_k_opt(t_des *des, t_opt *opt, int in_fd)
{
	t_btk_md5_params	params;
	char	buf[8];

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
			if (read(in_fd, buf, 8) != 8)
				return (0);
			if (ft_strncmp(buf, "Salted__", 8))
			{
				return (0);
			}
			if (read(in_fd, des->salt, 8) != 8)
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
		des->salted = 1;
		des->ived = 1;
	}
	return (1);
}

int	handle_v_e_d_opt(t_des *des, t_opt *opt)
{
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
	return (1);
}

int	handle_i_opt(t_des *des, t_opt *opt, int *in_fd)
{
	struct stat	s_buf;

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
	return (1);
}
