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
	// print_block_as_hex(key);
	print_binary((void*)&key, 28, 7);
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
	print_binary((void*)&key, 48, 6);
	printf("\n");
}

t_uint48	calculate_key(uint64_t c, uint64_t d)
{
	t_uint48	ret;
	uint64_t	pair;
	uint64_t	reti;

	pair = c | end_conv_64(end_conv_64(d) >> 28);
	permutate((void*)&pair, (void*)&reti, g_des_pc_two, 48);
	ret.x = reti;
	return (ret);
}

void	compute_key_schedule(t_uint48 out[16], uint64_t key)
{
	uint32_t	c; // 28 bit
	uint32_t	d; // 28 bit
	size_t		i;

	c = 0;
	d = 0;
	permutate((void*)&key, (void*)&c, g_des_pc_one_left, 28);
	permutate((void*)&key, (void*)&d, g_des_pc_one_right, 28);
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
		out[i - 1] = calculate_key(c, d);
		// printf("out[%2zu] : ", i - 1);
		// print_48_key(out[i - 1]);
	}
}
