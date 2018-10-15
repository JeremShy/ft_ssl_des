#include <ft_ssl.h>
#include <ft_printf.h>

void	print_block_as_hex(uint64_t in)
{
	printf("block : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3), *(((char*)&in) + 4), *(((char*)&in) + 5), *(((char*)&in) + 6), *(((char*)&in) + 7));
}

void	print_binary(uint8_t *in, size_t size, size_t blocks)
{
	size_t	i;

	i = 0;
	while (i < size)
	{
		printf("%d", !!((in[i / 8] << (i % 8)) & 0x80));
		i++;
		if (i % blocks == 0)
			printf(" ");
	}
}


void print_half_key(uint64_t key)
{
	int	i;

	// print_block_as_hex(key);
	print_binary((void*)&key, 28, 8);
	printf("\n");
}

void print_key(uint64_t key)
{
	// print_block_as_hex(key);
	print_binary((void*)&key, 64, 8);
	printf("\n");
}

void print_48_key(t_uint48 key)
{
	print_binary((void*)&key, 48, 8);
	printf("\n");
}

t_uint48	calculate_key(uint64_t c, uint64_t d)
{
	t_uint48	ret;
	uint64_t	pair;

	// pair = (c) | (d << );
	int	i = 0;
	// print_half_key(d);
	// print_binary((void*)&d, 56, 8);
	ft_printf("%r\n", d);
	printf("\n\n");
	// while (i < 64)
	// {
	// 	pair = pair << 1;
	// 	// print_binary((void*)&pair, 56, 8);
	// 	ft_printf("%r\n", pair);
	// 	i++;
	// }
	// exit(0);
	pair = ((c << 32) | d);
	print_block_as_hex(d);
	print_block_as_hex(pair);

	printf("---------------\nc : ");
	// print_half_key(c);
	ft_printf("%.32r\n", c);
	printf("d : ");
	// print_half_key(d);
	ft_printf("%.32r\n", d);
	printf("pair : ");
	// print_binary((void*)&pair, 56, 28);
	ft_printf("%r", pair);
	printf("\n----------------\n");

	return (ret);
}

void	compute_key_schedule(t_uint48 out[16], uint64_t key)
{
	uint32_t	c; // 28 bit
	uint32_t	d; // 28 bit
	size_t		i;

	(void)out;
	printf("computing key schedule from key : \n");
	print_key(key);

	permutate((void*)&key, (void*)&c, g_des_pc_one_left, 28);
	permutate((void*)&key, (void*)&d, g_des_pc_one_right, 28);

	// printf("Got keys : c[0] :\n");
	// print_half_key(c);
	// printf("And : d[0] :\n");
	// print_half_key(d);
	i = 0;
	while (i < 16)
	{
		if (g_des_lshift[i] == 1)
		{
			permutate((void*)&c, (void*)&c, g_des_rotl_1, 28);
			permutate((void*)&d, (void*)&d, g_des_rotl_1, 28);
		}
		else
		{
			permutate((void*)&c, (void*)&c, g_des_rotl_2, 28);
			permutate((void*)&d, (void*)&d, g_des_rotl_2, 28);
		}
		i++;
		out[i] = calculate_key(c, d);
	}
}
