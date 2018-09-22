#include <ft_ssl.h>

/*
	** transforms an ASCII representation of bytes (e.g. the c string "6061626360616263\0") into 
	** into its size bytes representation (e.g. the byte arrray \x60\x61\x62\x63\x60\x61\x62\x63).
	** If the str represents more than size bytes, it will be truncated so that out represents size bytes.
	** If it represents less, it will be left-padded with zeros (\x00).

	** out MUST be able to countains at least size bytes.
*/

void	hex_string_to_bytes(const char *str, unsigned char *out, size_t size)
{

}