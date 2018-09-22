#include <ft_ssl.h>

int	main_base64(t_opt *opt)
{
	int	in_fd;
	int	out_fd;
	if ((opt->flags & D_OPT && opt->flags & E_OPT) || (!(opt->flags & D_OPT) && !(opt->flags & E_OPT)))
	{
		ft_putstr_fd("Error : You must specify one of -d (decode) and -e (encode).\n", 2);
		return (0);
	}
	in_fd = 0;
	out_fd = 1;
	if (opt->flags & I_OPT)
	{
		if ((in_fd = open(opt->i_option, O_RDONLY)) == -1)
		{
			ft_putstr_fd("Couldn't open file ", 2);
			ft_putstr_fd(opt->i_option, 2);
			ft_putstr_fd(" for reading.\n", 2);
			return (0);
		}
	}
	if (opt->flags & O_OPT)
	{
		if ((out_fd = open(opt->o_option, O_WRONLY | O_CREAT, 0666)) == -1)
		{
			ft_putstr_fd("Couldn't open file ", 2);
			ft_putstr_fd(opt->o_option, 2);
			ft_putstr_fd(" for writing.\n", 2);
			return (0);
		}
	}
	if (opt->flags & E_OPT)
		base64_encode_from_fd(opt, in_fd, out_fd);
	else if (opt->flags & D_OPT)
		base64_decode_from_fd(opt, in_fd, out_fd);
	return (1);
}