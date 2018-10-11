#!/usr/bin/env python3
import subprocess
from termcolor import colored
PROGRAM_NAME = "./ft_ssl"

current_nfalse = 0
current_test_nbr = 0

def check_hmac_sha1(key, data, expected_output):
	global current_nfalse
	global current_test_nbr

	expected_output += "\n"
	current_test_nbr += 1
	result = subprocess.run([PROGRAM_NAME, "hmac-sha1", b"-k" + key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)
	out = result.stdout.decode("ascii")
	if result.stderr != b'':
		print (colored("Error", 'red'), " : Stderr not empty (", result.stderr, ") [", current_test_nbr, "]")
	elif out != expected_output:
		print (colored("Error", 'red'), " : [", expected_output, "] != [", out, "] [", current_test_nbr, "]")
	else:
		print (colored("OK", 'green'), "[", current_test_nbr, "]")
		return (True)
	current_nfalse += 1
	return (False)


def RUN_HMAC_SHA1_TESTS():
	global current_nfalse
	global current_test_nbr

	print ("HMAC_SHA1 : ")

	current_nfalse = 0;
	current_test_nbr = 0
	check_hmac_sha1(b"\x0b" * 20, b"Hi There", "b617318655057264e28bc0b6fb378c8ef146be00")
	check_hmac_sha1(b"Jefe", b"what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
	check_hmac_sha1(b"\xaa" * 20, b"\xdd" * 50, "125d7342b9ac11cd91a39af48aa17b4f63f175d3")
	check_hmac_sha1(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", b"\xcd" * 50, "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
	check_hmac_sha1(b"\x0c" * 20, b"Test With Truncation", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")
	check_hmac_sha1(b"\xaa" * 80, b"Test Using Larger Than Block-Size Key - Hash Key First", "aa4ae5e15272d00e95705637ce8a3b55ed402112")
	check_hmac_sha1(b"\xaa" * 80, b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91")

	print("Number of false : ( {} / {} )".format(colored(current_nfalse, "red"), colored(current_test_nbr, "green")))


def main():
	RUN_HMAC_SHA1_TESTS()

if __name__ == '__main__':
	main()
