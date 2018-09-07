#include <ft_ssl.h>

int	main_base64(t_opt *opt)
{
	if ((opt->flags & D_OPT && opt->flags & E_OPT) || (!(opt->flags & D_OPT) && !(opt->flags & E_OPT)))
	{
		ft_putstr_fd("Error : You must specify one of -d (decode) and -e (encode).\n", 2);
		return (0);
	}
	if (opt->flags & E_OPT)
		base64_encode_from_fd(opt, 0);
	return (1);
}
