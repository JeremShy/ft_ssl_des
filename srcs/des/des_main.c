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
	printf("content : %s\n", opt->content);
}

static int	compute_des(t_des *des, t_opt *opt, int *in_fd)
{
	ft_bzero(des, sizeof(t_des));
	if (!handle_v_e_d_opt(des, opt))
		return (0);
	if (!handle_i_opt(des, opt, in_fd))
		return (0);
	if (!handle_k_opt(des, opt, *in_fd))
		return (0);
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
