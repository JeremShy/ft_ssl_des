#include <ft_ssl.h>

static const int *get_s_box(size_t i)
{
	if (i == 0)
		return g_des_one;
	else if (i == 1)
		return g_des_two;
	else if (i == 2)
		return g_des_three;
	else if (i == 3)
		return g_des_four;
	else if (i == 4)
		return g_des_five;
	else if (i == 5)
		return g_des_six;
	else if (i == 6)
		return g_des_seven;
	else if (i == 7)
		return g_des_eight;
	else
		return NULL;
}

uint32_t	compute_s_box(t_uint48 in, size_t i)
{
	const int	*s_box;
	uint8_t		row;
	uint8_t		col;

	s_box = get_s_box(i);
	printf("computing s_box %zu for block : ", i);
	print_binary((void*)&in, 48, 6);
	return (0);
}
