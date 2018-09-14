#include <ft_ssl.h>

char	*get_file(int fd, int *in_size)
{
	char	buffer[4096];
	int		r;
	char	*ret;
	char	*tmp;

	*in_size = 0;
	ret = NULL;
	while ((r = read(fd, buffer, 4095)) > 0)
	{
		buffer[r] = '\0';
		if (!ret)
		{
			ret = malloc(r);
			ft_memcpy(ret, buffer, r);
		}
		else
		{
			tmp = ret;
			ret = malloc(*in_size + r);
			ft_memcpy(ret, tmp, *in_size);
			ft_memcpy(ret + *in_size, buffer, r);
			free(tmp);
		}
		*in_size += r;
	}
	if (r < 0)
		ret = NULL;
	if (!ret)
		ret = ft_strdup("");
	return (ret);
}