/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parsing.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jcamhi <jcamhi@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/08 17:56:45 by jcamhi            #+#    #+#             */
/*   Updated: 2018/07/08 19:03:06 by jcamhi           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <ft_ssl.h>

static int	has_argument(char c, int (*fun) (t_opt*))
{
	if (fun == main_des_ecb || fun == main_des_cbc)
	{
		if (c == 'i' || c == 'k' || c == 'o' || c == 'p' || c == 's' || c == 'v')
			return (1);
		else
			return (0);
	}
	else if (c == 's' || c == 'i' || c == 'o')
			return (1);
		else
			return (0);
}

static int	print_str_and_ret(char *str1, char c)
{
	ft_putstr_fd(str1, 2);
	write(2, &c, 1);
	ft_putstr_fd("\n", 2);
	return (0);
}

static int	get_option(char *option, t_opt *opt, int (*fun) (t_opt*))
{
	int	i;

	i = 1;
	while (option[i])
	{
		if ((option[i] >= 'p' && option[i] <= 's') || option[i] == 'e' || option[i] == 'd' || option[i] == 'i' || option[i] == 'o' || option[i] == 'v' || option[i] == 'a')
		{
			if (option[i] >= 'p' && option[i] <= 's')
				opt->flags |= 1 << (option[i] - 'p');
			else if (option[i] == 'd')
				opt->flags |= D_OPT;
			else if (option[i] == 'e')
				opt->flags |= E_OPT;
			else if (option[i] == 'i')
				opt->flags |= I_OPT;
			else if (option[i] == 'o')
				opt->flags |= O_OPT;
			else if (option[i] == 'v')
				opt->flags |= A_OPT;
			else if (option[i] == 'a')
				opt->flags |= A_OPT;
		}
		else
			return (print_str_and_ret("Illegal option: ", option[i]));
		if (opt->flags & S_OPT)
		{
			opt->content = option[i + 1] == '\0' ? NULL : option + i + 1;
			return (1);
		}
		else if (opt->flags & P_OPT && (has_argument('p', fun)))
		{
			opt->content = NULL;
			fun(opt);
			opt->flags &= ~P_OPT;
		}
		else if (opt->flags & I_OPT && opt->i_option == NULL)
		{
			opt->i_option = option[i + 1] == '\0' ? NULL : option + i + 1;
			return (1);
		}
		else if (opt->flags & O_OPT && opt->o_option == NULL)
		{
			opt->o_option = option[i + 1] == '\0' ? NULL : option + i + 1;
			return (1);
		}
		else if (opt->flags & P_OPT && opt->p_option == NULL && has_argument('p', fun))
		{
			opt->p_option = option[i + 1] == '\0' ? NULL : option + i + 1;
			return (1);
		}
		else if (opt->flags & S_OPT && opt->s_option == NULL && has_argument('s', fun))
		{
			opt->s_option = option[i + 1] == '\0' ? NULL : option + i + 1;
			return (1);
		}
		else if (opt->flags & O_OPT && opt->o_option == NULL)
		{
			opt->o_option = option[i + 1] == '\0' ? NULL : option + i + 1;
			return (1);
		}
		i++;
	}
	return (1);
}

static int	handle_s_opt(t_opt *opt, int (*fun)(t_opt*), char **av, int *i)
{
	if (!opt->content)
	{
		if (!av[*i + 1])
			return (0);
		opt->content = av[*i + 1];
		(*i)++;
	}
	fun(opt);
	opt->flags &= ~S_OPT;
	return (1);
}

static int		handle_parametrized_opt(char **av, int *i, t_opt *opt)
{
	if (!av[*i + 1])
		return (0);
	if ((opt->flags & I_OPT) && opt->i_option == NULL)
		opt->i_option = av[*i + 1];
	else if ((opt->flags & O_OPT) && opt->o_option == NULL)
		opt->o_option = av[*i + 1];
	else
		return (0);
	(*i)++;
	return (1);
}

static int	do_parsing(char **av, t_opt *opt, int (*fun) (t_opt*))
{
	int	i;
	int	ignore;

	i = 2;
	ignore = 0;
	while (av[i])
	{
		if (av[i][0] == '-' && !ignore)
		{
			if (!get_option(av[i], opt, fun))
				return (0);
			if (((opt->flags & I_OPT) && opt->i_option == NULL) || ((opt->flags & O_OPT) && opt->o_option == NULL))
				{
					if (handle_parametrized_opt(av, &i, opt) == 0)
						return (0);
				}
			if (opt->flags & S_OPT && handle_s_opt(opt, fun, av, &i) == 0)
				return (0);
		}
		else
		{
			opt->content = av[i];
			fun(opt);
			ignore = 1;
		}
		i++;
	}
	if (opt->content == NULL && !(av[2] && !av[3] && ft_strequ("-p", av[2])))
		fun(opt);
	return (1);
}

int			parse_options(int ac, char **av, t_opt *opt)
{
	int (*fun) (t_opt*);

	if (ac < 2)
		return (0);
	ft_bzero(opt, sizeof(t_opt));
	if (ft_strequ(av[1], "md5"))
		fun = main_md5;
	else if (ft_strequ(av[1], "sha256"))
		fun = main_256;
	else if (ft_strequ(av[1], "base64"))
		fun = main_base64;
	else if (ft_strequ(av[1], "des") || ft_strequ(av[1], "des-ecb"))
		fun = main_des_ecb;
	else if (ft_strequ(av[1], "des-cbc"))
		fun = main_des_cbc;
	else
	{
		ft_putstr_fd("Unknown algorithm: ", 2);
		ft_putstr_fd(av[1], 2);
		ft_putstr_fd("\n", 2);
		return (0);
	}
	if (!do_parsing(av, opt, fun))
		return (0);
	return (1);
}
