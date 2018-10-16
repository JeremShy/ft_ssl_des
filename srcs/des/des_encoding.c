#include <ft_ssl.h>

/*
	* Datalen is in bytes size. 
*/

void	print_block_as_char(uint64_t in)
{
	printf("block : %c%c%c%c%c%c%c%c\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3), *(((char*)&in) + 4), *(((char*)&in) + 5), *(((char*)&in) + 6), *(((char*)&in) + 7));
}

void	print_half_block_as_char(uint32_t in)
{
	printf("half_block : %c%c%c%c\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3));
}

void	divide_block(uint8_t *out, t_uint48 in)
{
	uint64_t	in_x;
	uint64_t	mask;

	mask = 0x3F;
	in_x = in.x;
	in_x = end_conv_64(in_x) >> 16;
	ft_bzero(out, 8 * sizeof(char));
	out[0] = (in_x & (mask << 42)) >> 42;
	out[1] = (in_x & (mask << 36)) >> 36;
	out[2] = (in_x & (mask << 30)) >> 30;
	out[3] = (in_x & (mask << 24)) >> 24;
	out[4] = (in_x & (mask << 18)) >> 18;
	out[5] = (in_x & (mask << 12)) >> 12;
	out[6] = (in_x & (mask << 6)) >> 6;
	out[7] = (in_x & (mask << 0)) >> 0;

	// int i = 0;
	// while (i < 8)
	// {
	// 	printf("out[%d] : ", i);
	// 	ft_printf("%.6r", out[i]);
	// 	printf("\n");
	// 	i++;
	// }
}

void	do_iteration(t_uint48 ks[16], uint32_t *l, uint32_t *r, size_t i)
{
	uint32_t	lp;
	uint32_t	rp;
	t_uint48	eed;
	t_uint48	xored;
	uint8_t		blocks[8];
	uint32_t	p;

	lp = *r;

	permutate((void*)r, (void*)&eed, g_des_e, 48);

		// printf("after passing through e : ");
		// print_binary((void*)&eed, 48, 6);
		// printf("\nkey : ");
		// print_binary((void*)&ks[i], 48, 6);
		// printf("\n");

	xored.x = eed.x ^ ks[i].x;

		// printf("xored : ");
		// print_binary((void*)&xored, 48, 6);
		// printf("\n");
	divide_block(blocks, xored);
		// printf("\n");
	int	z = 0;
	uint32_t	s_box_r = 0;
	while (z < 8)
	{
		s_box_r <<= 4;
		s_box_r |= compute_s_box(blocks[z], z);
			// print_binary((void*)&s_box_r, 32, 4);
			// printf("\n");
		z++;
	}
	s_box_r = end_conv_32(s_box_r);
		// print_binary((void*)&s_box_r, 32, 4);
		// printf("\n");
	permutate((void*)&s_box_r, (void*)&p, g_des_p, 32);
		printf("p : ");
		print_binary((void*)&p, 32, 4);
		printf("\n");

		printf("l : ");
		print_binary((void*)l, 32, 4);
		printf("\n");

	rp = p ^ *l;

		printf("r : ");
		print_binary((void*)&p, 32, 4);
		printf("\n");

	exit(0);


	*l = lp;
	*r = rp;
}

uint64_t	encode_block(t_des *des, const uint64_t in, t_uint48 ks[16])
{
	uint64_t	out;
	uint32_t	l;
	uint32_t	r;

	(void)des;
	permutate((const void*)&in, (void *)&out, g_des_ip, 64);

	l = *(uint32_t*)&out;
	r = *(((uint32_t*)&out) + 1);
	int	i = 0;
	while (i < 16)
	{
		do_iteration(ks, &l, &r, i);
		i++;
	}
	permutate((const void*)&out, (void *)&out, g_des_ip_inv, 64);
	return (out);
}

uint32_t	*des_encode(t_des *des, const uint8_t *data, size_t datalen, t_mode mode)
{
	size_t				n;
	uint64_t		*ret;
	const uint64_t	*in;
	t_uint48	ks[16];

	(void)mode;
	compute_key_schedule(ks, *(uint64_t*)des->key);
	printf("About to encode : [%s] - size : %zu\n", data, datalen);
	if (!(ret = malloc(datalen * sizeof(char))))
	{
		ft_putendl_fd("Error : Could not allocate enough space.", 2);
		return (NULL);
	}
	in = (const void*)data;
	n = 0;
	while (n < datalen / 8)
	{
		ret[n] = encode_block(des, in[n], ks);
		n++;
	}
	printf("Encoded value : %.*s\n", (int)datalen, (void*)ret);
	return (NULL);
}

/*
	* encode_block encodes a 64bit (8 bytes) long block, into another 64bit
	*  long block.
	* There are 8 chars in a block.
*/
