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
	xored.x = eed.x ^ ks[i].x;
	divide_block(blocks, xored);
	int	z = 0;
	uint32_t	s_box_r = 0;
	while (z < 8)
	{
		s_box_r <<= 4;
		s_box_r |= compute_s_box(blocks[z], z);
		z++;
	}
	s_box_r = end_conv_32(s_box_r);
	permutate((void*)&s_box_r, (void*)&p, g_des_p, 32);
	rp = p ^ *l;
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
	*(uint32_t*)&out = r;
	*((uint32_t*)&out + 1) = l;
	permutate((const void*)&out, (void *)&out, g_des_ip_inv, 64);
	return (out);
}

void	swap_ks(t_uint48 ks[16])
{
	t_uint48	cpy[16];

	ft_memcpy(cpy, ks, 16 * sizeof(t_uint48));
	ks[0] = cpy[15];
	ks[1] = cpy[14];
	ks[2] = cpy[13];
	ks[3] = cpy[12];
	ks[4] = cpy[11];
	ks[5] = cpy[10];
	ks[6] = cpy[9];
	ks[7] = cpy[8];
	ks[8] = cpy[7];
	ks[9] = cpy[6];
	ks[10] = cpy[5];
	ks[11] = cpy[4];
	ks[12] = cpy[3];
	ks[13] = cpy[2];
	ks[14] = cpy[1];
	ks[15] = cpy[0];
}

void	remove_padding(const uint8_t *data, size_t *datalen, uint8_t *ret)
{
	int	padd_size = data[*datalen - 1];

	ret[*datalen - padd_size] = '\0';
	*datalen = *datalen - padd_size;
}

uint32_t	*des_encode(t_des *des, const uint8_t *data, size_t datalen, t_mode mode)
{
	size_t				n;
	uint64_t		*ret;
	uint64_t	*in;
	uint64_t	last_block;
	t_uint48	ks[16];

	if (mode == cbc)
		last_block = *(uint64_t*)des->iv;
	if (des->encode)
		data = pkcs5_padding(data, &datalen, 8);
	else if ((datalen / 8) * 8 != datalen)
	{
		ft_putendl_fd("Error : The size of the data to decrypt isn't a multiple 64 bit.", 2);
		return (NULL);
	}

	compute_key_schedule(ks, *(uint64_t*)des->key);
	if (des->encode == 0)
	{
		swap_ks(ks);
	}
	if (!(ret = malloc(datalen * sizeof(char))))
	{
		ft_putendl_fd("Error : Could not allocate enough space.", 2);
		return (NULL);
	}
	in = (void*)data;
	n = 0;
	while (n < datalen / 8)
	{
		if (mode == cbc && des->encode == 1)
			in[n] ^= last_block;
		ret[n] = encode_block(des, in[n], ks);
		if (mode == cbc && des->encode == 1)
			last_block = ret[n];
		else if (mode == cbc && des->encode == 0)
		{
			if (n == 0)
				ret[n] ^= last_block;
			else
				ret[n] ^= in[n - 1];
		}
		n++;
	}
	if (des->encode == 0)
		remove_padding((void*)ret, &datalen, (uint8_t*)ret);
	if (des->salted && des->encode == 1)
	{
		write(des->out_fd, "Salted__", 8);
		write(des->out_fd, des->salt, 8);
	}
	write(des->out_fd, ret, datalen);
	return (NULL);
}

/*
	* encode_block encodes a 64bit (8 bytes) long block, into another 64bit
	*  long block.
	* There are 8 chars in a block.
*/
