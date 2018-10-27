#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import shutil
import os

from termcolor import colored
PROGRAM_NAME = os.getcwd() + "/ft_ssl"

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

def check_des_ecb(key, data, expected_output, decrypt, mine = True):
	global current_nfalse
	global current_test_nbr

	if (decrypt == True):
		mode = "-d"
	else:
		mode = "-e"

	current_test_nbr += 1

	if (mine == True):
		result = subprocess.run([PROGRAM_NAME, "des-ecb", mode, b"-k" + key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)
	else:
		result = subprocess.run(["openssl", "des-ecb", mode, b"-K", key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)

	if result.stderr != b'':
		print (colored("Error", 'red'), " : Stderr not empty (", result.stderr, ") [", current_test_nbr, "]")
	elif result.stdout != expected_output:
		print (colored("Error", 'red'), " : [", expected_output, "] != [", result.stdout, "] [", current_test_nbr, "]")
	else:
		print (colored("OK", 'green'), "[", current_test_nbr, "]")
		return (True)
	current_nfalse += 1
	return (False)

def	check_parse_error(command, expected_output, error_on_empty_stdout=True):
	global current_nfalse
	global current_test_nbr

	current_test_nbr += 1

	command = [PROGRAM_NAME] + command

	result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	if (error_on_empty_stdout and result.stdout != b''):
		print (colored("Error", 'red'), " : Stdout not empty (", result.stdout, ") [", current_test_nbr, "]")
	elif (result.stderr != expected_output):
		print (colored("Error", 'red'), " : [", expected_output, "] != [", result.stderr, "] [", current_test_nbr, "]")
	else:
		print (colored("OK", 'green'), "[", current_test_nbr, "]")
		return (True)
	current_nfalse += 1
	return (False)

def check_des_cbc(key, iv, data, expected_output, decrypt, mine = True, against_real_one=False):
	global current_nfalse
	global current_test_nbr

	if (decrypt == True):
		mode = "-d"
	else:
		mode = "-e"

	current_test_nbr += 1

	if (against_real_one == False):
		if (mine == True):
			result = subprocess.run([PROGRAM_NAME, "des-cbc", mode, b"-k" + key, "-v", iv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)
		else:
			result = subprocess.run(["openssl", "des-cbc", mode, b"-K", key, "-iv", iv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)
	else:
		result = subprocess.run([PROGRAM_NAME, "des-cbc", mode, b"-k" + key, "-v", iv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)
		other = subprocess.run(["openssl", "des-cbc", mode, b"-K", key, "-iv", iv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=data)
		expected_output = other.stdout

	if result.stderr != b'':
		print (colored("Error", 'red'), " : Stderr not empty (", result.stderr, ") [", current_test_nbr, "]")
	elif result.stdout != expected_output:
		print (colored("Error", 'red'), " : [", expected_output, "] != [", result.stdout, "] [", current_test_nbr, "]")
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


def RUN_DES_ECB_TESTS():
	global current_nfalse
	global current_test_nbr
	print ("DES_ECB : ")
	current_nfalse = 0
	current_test_nbr = 0

	check_des_ecb(b"133457799BBCDFF1", b"jcamhi\n", b"\xf2\x9e\xc5\x74\xd3\xbe\x8e\xb6", False)
	check_des_ecb(b"133457799BBCDFF1", b"jcamhi\n", b"\xf2\x9e\xc5\x74\xd3\xbe\x8e\xb6", False, mine=False)
	check_des_ecb(b"133457799BBCDFF1", b"\xf2\x9e\xc5\x74\xd3\xbe\x8e\xb6",  b"jcamhi\n", True, mine=False)

	check_des_ecb(b"133457799BBCDFF1", b"salutcavajesuisbeauetforthahahahahaha", b"\x4d\x7f\x30\x1a\xfe\x18\x94\xe9\x61\xe2\x8d\xc3\xb0\x17\xd2\xe5\x9e\xb8\x8b\x77\xfe\x70\x3f\x58\x36\x9d\x49\x7c\xdb\xb0\x85\x0b\xf9\xc7\x64\x43\x3a\xfe\x0d\xc0", False)
	check_des_ecb(b"133457799BBCDFF1", b"\x4d\x7f\x30\x1a\xfe\x18\x94\xe9\x61\xe2\x8d\xc3\xb0\x17\xd2\xe5\x9e\xb8\x8b\x77\xfe\x70\x3f\x58\x36\x9d\x49\x7c\xdb\xb0\x85\x0b\xf9\xc7\x64\x43\x3a\xfe\x0d\xc0", b"salutcavajesuisbeauetforthahahahahaha", True)

	print("Number of false : ( {} / {} )".format(colored(current_nfalse, "red"), colored(current_test_nbr, "green")))

def RUN_DES_CBC_TESTS():
	global current_nfalse
	global current_test_nbr
	print ("DES_CBC : ")
	current_nfalse = 0
	current_test_nbr = 0

	check_des_cbc(b"133457799BBCDFF1", b"0000000000000000", b"jcamhi\n", b"\xf2\x9e\xc5\x74\xd3\xbe\x8e\xb6", False)
	check_des_cbc(b"133457799BBCDFF1", b"0000000000000000", b"jcamhi\n", b"\xf2\x9e\xc5\x74\xd3\xbe\x8e\xb6", False, mine=False)
	check_des_cbc(b"133457799BBCDFF1", b"12345689AB000000", b"jcamhi\n", b"\x3c\x13\x1c\x13\xd7\x25\xe7\x42", False)
	check_des_cbc(b"133457799BBCDFF1", b"12345689AB000000", b"jcamhi\n", b"\x3c\x13\x1c\x13\xd7\x25\xe7\x42", False, mine=False)
	check_des_cbc(b"133457799BBCDFF1", b"12345689AB000000", b"Test Using Larger Than One Block-Size Data", b"", False, against_real_one=True,)
	print("Number of false : ( {} / {} )".format(colored(current_nfalse, "red"), colored(current_test_nbr, "green")))


def RUN_PARSING_TESTS():
	global current_nfalse
	global current_test_nbr
	print ("PARSING : ")
	current_nfalse = 0
	current_test_nbr = 0

	temp_dir = tempfile.mkdtemp(prefix="testing_", dir=".");
	os.chdir(temp_dir)

	check_parse_error([b'des'], b"Error : You must specify one of -e or -d\n")
	check_parse_error([b'dex'], b'Unknown algorithm: dex\n\nStandard commands\n\nMessage Digest commands\nmd5\tsha1\tsha256\tsha512\n\nCipher commands\nbase64\tdes\tdes-cbc\tdes-ecb\n\n')
	check_parse_error([b'des', b'-e', b'-ix'], b'Error while trying to open file for reading.\n')
	
	check_parse_error([b'des', b'-e', b'-i.', '-pa'], b"Can't stat input file, or the input file is a folder.\n")

	check_parse_error([b'des', b'-d', b'-i', b'../Makefile', '-kz'], b'Error : Problem while parsing the key\n')
	check_parse_error([b'des', b'-d', b'-i', b'../Makefile', '-vaz'], b'Error : Problem while parsing the iv\n')
	check_parse_error([b'des', b'-d', b'-i', b'../Makefile', '-va', '-kz'], b'Error : Problem while parsing the key\n')
	check_parse_error([b'des', b'-i', b'../Makefile', '-va'], b'Error : You must specify one of -e or -d\n')

	os.chdir("..")
	shutil.rmtree(temp_dir)

def main():
	global current_nfalse
	global current_test_nbr

	total_nfalse = 0
	total_test_nbr = 0

	RUN_PARSING_TESTS()
	total_nfalse += current_nfalse
	total_test_nbr += current_test_nbr
	RUN_HMAC_SHA1_TESTS()
	total_nfalse += current_nfalse
	total_test_nbr += current_test_nbr
	RUN_DES_ECB_TESTS()
	total_nfalse += current_nfalse
	total_test_nbr += current_test_nbr
	RUN_DES_CBC_TESTS()
	total_nfalse += current_nfalse
	total_test_nbr += current_test_nbr

	print("------------------------")
	print("Total number of false : ( {} / {} )".format(colored(total_nfalse, "red"), colored(total_test_nbr, "green")))
	return total_nfalse

if __name__ == '__main__':
	sys.exit(main())

