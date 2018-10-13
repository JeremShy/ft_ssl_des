#include <ft_ssl.h>

void	print_block_as_hex(uint64_t in)
{
	printf("block : %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3), *(((char*)&in) + 4), *(((char*)&in) + 5), *(((char*)&in) + 6), *(((char*)&in) + 7));
}

void	print_binary(uint8_t in)
{
	int	i;

	i = 0;
	while (i < 8)
	{
		printf("%d", !!((in << i) & 0x80));
		i++;
	}
}


void print_key(uint64_t key)
{
	int	i;

	print_block_as_hex(key);
	i = 0;
	while (i < 8)
	{
		print_binary(*(((uint8_t*)&key) + i));
		printf(" ");
		i++;
	}
	printf("\n");
}

void	compute_key_schedule(t_uint48 out[16], uint64_t key)
{
	uint32_t	c; // 28 bit
	uint32_t	d; // 28 bit
	size_t		i;

	printf("computing key schedule from key : \n");
	print_key(key);

	permutate((void*)&key, (void*)&c, g_des_pc_one_left, 28);
	permutate((void*)&key, (void*)&d, g_des_pc_one_right, 28);

	printf("Got keys : c[0] :\n");
	print_key(c);
	printf("And : d[0] :\n");
	print_key(d);
	i = 0;
	while (i < 16)
	{
		c = rotl_28(g_des_lshift[i], c);
		d = rotl_28(g_des_lshift[i], d);
		printf("Got keys : c[%zu] << %d :\n", i + 1, g_des_lshift[i]);
		print_key(c);
		// printf("Got keys : d[%zu] << %d :\n", i, g_des_lshift[i]);
		// print_key(d);
		i++;
	}
}
