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
	ft_bzero(des, sizeof(t_des));
	if (opt->flags & K_OPT && opt->k_option)
	{
		// Key provided, must do the padding.
	}
	else if (opt->flags & P_OPT && opt->p_option)
	{
		// password provided, must compute the key from the password using a randomly generated salt, and pbkdf2
		des->salted = 1;
	}
	else
	{
		ft_putendl_fd("Error : You must specify at least a password or a key.", 2);
		return (0);
	}

	if (opt->flags & I_OPT)
	{
		des->ived = 1;
		// IV provided, must fill it.
	}
	return (1);
}

int	main_des_ecb(t_opt *opt)
{
	t_des	des;

	printf("Called des_ecb\n");
	print_opt(opt);

	if (!(compute_des(&des, opt)))
		return (0);

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