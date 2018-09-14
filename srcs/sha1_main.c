#include <ft_ssl.h>

void	do_sha1(int in_fd, int out_fd, char *in_filename)
{
	char	*file;
	int		in_size;
	char	*out;

	file = get_file(in_fd, &in_size);
	out = sha1_encode(file, in_size);
	ft_putstr_fd(in_filename, out_fd);
	ft_putstr_fd("= ", out_fd);
	ft_putendl_fd(out, out_fd);
	free(out);
	free(file);
}

int	main_sha1(t_opt *opt)
{
	int	in_fd;
	int		out_fd;

	if (opt->flags & I_OPT)
	{
		if (!opt->i_option)
			return (0);
		in_fd = open(opt->i_option, O_RDONLY);
		if (in_fd == -1)
			return (0);
	}
	else
		in_fd = 0;
	if (opt->flags & O_OPT)
	{
		if (!opt->o_option)
			return (0);
		out_fd = open(opt->o_option, O_RDONLY);
		if (out_fd == -1)
			return (0);
	}
	else
		out_fd = 1;
	do_sha1(in_fd, out_fd, (opt->flags & I_OPT && opt->i_option != NULL ? opt->i_option : "(stdin)"));
	return (1);
}