/*
    command-line tool to extract partitions of Grandstream GXP firmware image
    Copyright (C) 2019 eelogic*2x4logic^com

    Permission is hereby granted, free of charge, to any person obtaining a 
    copy of this software and associated documentation files (the "Software"), 
    to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, 
    and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in 
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
    DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include "aes.h"
#include "key.h"

#define MAGIC_SIGNATURE 0x23C97AF9

struct part_header
{
	uint32_t signature;
	uint32_t version;
	uint32_t partition_size;
	uint32_t image_size;
	uint16_t id;
	uint16_t checksum;
	uint16_t year;
	uint8_t day;
	uint8_t month;
	uint8_t minute;
	uint8_t hour;
	uint16_t hwid;
	uint16_t mask[2];
};

static uint32_t sizes[8];
static uint8_t filenames[8][64];
static uint32_t versions[8];

/* part of a nasty hack to handle the variations between versions of firmware */
static struct personality_struct
{
	const char *prefix;
	int max_file_entries;
	bool extra_file;
} personalities[] =
{
	{
		.prefix = "gxp21",
		.max_file_entries = 6,
		.extra_file = true,
	},
	{
		.prefix = "gxp1",
		.max_file_entries = 8,
		.extra_file = false,
	},
};

int main(int argc, char *argv[])
{
	struct AES_ctx ctx;
	int index, image_count, i;
	uint8_t buffer[32];
	FILE *input, *output;
	uint32_t signature = 0;
	long file_size, image_sum, header_size, remaining;
	struct part_header header;
	uint8_t part_key[16];
	uint8_t *pnt;
	struct personality_struct *personality_pnt = NULL;
	uint16_t image_checksum, chksum;

	/* open file and check signature */

	input = fopen(argv[1], "rb");

	if (!input)
		return -1;

	fread(&signature, sizeof(signature), 1, input);

	if (MAGIC_SIGNATURE != signature)
	{
		fprintf(stderr, "ERROR: bad signature\n");
		return -1;
	}

	/* obtain file size (helpful for sanity checking) */

	fseek(input, 0, SEEK_END);
	file_size = ftell(input);
	fseek(input, 4, SEEK_SET);

	/* collect all the filenames */

	image_count = 0;

	for (;;)
	{
		if (sizeof(filenames) / sizeof(*filenames) == image_count)
		{
			fprintf(stderr, "ERROR: too many filenames\n");
			return -1;
		}

		if (!fread(&filenames[image_count], sizeof(*filenames), 1, input))
		{
			fprintf(stderr, "ERROR: premature EOF in filename table\n");
			return -1;
		}

		if (!filenames[image_count][0])
		{
			if (filenames[image_count][1] || filenames[image_count][2] || filenames[image_count][3])
				break;

			continue;
		}

		image_count++;
	}

	if (!image_count)
	{
		fprintf(stderr, "ERROR: no entries found in filename table\n");
		return -1;
	}

	for (index = 0; index < (sizeof(personalities) / sizeof(*personalities)); index++)
		if (0 == strncmp(filenames[0], personalities[index].prefix, strlen(personalities[index].prefix)))
		{
			personality_pnt = &personalities[index];
			break;
		}

	if (!personality_pnt)
	{
		fprintf(stderr, "ERROR: file doesn't correspond to known formats\n");
		return -1;
	}

	/* we've reached the end of the filenames and gone one step too far, so we backtrack by one */

	fseek(input, -sizeof(*filenames), SEEK_CUR);

	/* read the sizes of each of the images */

	for (index = 0, image_sum = 0; index < image_count; index++)
	{
		if (!fread(&sizes[index], sizeof(*sizes), 1, input))
		{
			fprintf(stderr, "ERROR: premature EOF in sizes\n");
			return -1;
		}

		image_sum += sizes[index];
	}

	fseek(input, (personality_pnt->max_file_entries - image_count) * sizeof(*sizes), SEEK_CUR);

	/* read the versions */

	for (index = 0; index < image_count; index++)
	{
		if (!fread(&versions[index], sizeof(*versions), 1, input))
		{
			fprintf(stderr, "ERROR: premature EOF in versions\n");
			return -1;
		}
	}

	/* determine the header size (varies between models) and sanity check it */

	header_size = file_size - image_sum;

	if (header_size <= 0)
	{
		fprintf(stderr, "ERROR: unexpected header format\n");
		return -1;
	}

	/* this is a particularly nasty hack for a strange older file revision */

	if (personality_pnt->extra_file)
	{
		/* GXP21xx firmware of an older vintage has a strange extra entry for the local partition */
		if (filenames[0][24])
		{
			strcpy(filenames[image_count], &filenames[0][24]);
			sizes[image_count] = header_size - 0x1C0;
			header_size = 0x1C0;
			image_sum += sizes[image_count];
			image_count++;
		}
	}

	/* sanity check the sizes of the images */

	for (index = 0; index < image_count; index++)
	{
		if (sizes[index] % sizeof(buffer))
		{
			fprintf(stderr, "ERROR: image size 0x%x of %s is unlikely given cipher algorithm\n", sizes[index], filenames[index]);
			return -1;
		}
	}

	fseek(input, header_size, SEEK_SET);

	/* verify that we shouldn't have to overwrite any existing files */

	for (index = 0; index < image_count; index++)
	{
		if (-1 != access(filenames[index], F_OK))
		{
			fprintf(stderr, "ERROR: file %s already exists\n", filenames[index]);
			return -1;
		}
	}

	/* iterate through each of the files */

	for (index = 0; index < image_count; index++)
	{
		if (fread(&header, sizeof(header), 1, input))
		{
			/* read the image header and decrypt with the default key */

			AES_init_ctx(&ctx, default_key);
			AES_ctx_set_iv(&ctx, iv);
			AES_CBC_decrypt_buffer(&ctx, (uint8_t *)&header, sizeof(header));

			/* sanity check the decrypted header */

			if (MAGIC_SIGNATURE != header.signature)
			{
				fprintf(stderr, "ERROR: image %s fails signature test\n", filenames[index]);
				return -1;
			}

			/* open the file to write the image to */

			output = fopen(filenames[index], "wb");

			if (!output)
			{
				fprintf(stderr, "ERROR: unable to open %s for writing\n", filenames[index]);
				return -1;
			}

			printf("writing %s (v%d.%d.%d.%d) chksum %04x", filenames[index],
				(header.version >> 24) & 0xFF, (header.version >> 16) & 0xFF, 
				(header.version >> 8) & 0xFF, (header.version >> 0) & 0xFF,
				header.checksum);
			printf(" %04d-%02d-%02d %02d:%02d\n", header.year, header.month, header.day,
				header.hour, header.minute);

			/* skip over the remainder of the 512 byte header */

			fseek(input, 0x200 - sizeof(header), SEEK_CUR);

			/* the image decryption key is derived from the header and only needs byte swapping */

			pnt = (uint8_t *)&header.id;
			for (i = 0; i < 16; i+=2)
			{
				part_key[i + 0] = pnt[i + 1];
				part_key[i + 1] = pnt[i + 0];
			}

			/* read encrypted data; write decrypted data; calc checksum along the way */

			image_checksum = 0;

			AES_init_ctx(&ctx, part_key);

			for (remaining = sizes[index] - 0x200; remaining; remaining -= sizeof(buffer))
			{
				fread(buffer, sizeof(buffer), 1, input);
				AES_ctx_set_iv(&ctx, iv);
				AES_CBC_decrypt_buffer(&ctx, buffer, sizeof(buffer));

				for (i = 0; i < sizeof(buffer); i += 2)
				{
					chksum = buffer[i + 1];
					chksum <<= 8;
					chksum += buffer[i + 0];
					image_checksum += chksum;
				}

				fwrite(buffer, sizeof(buffer), 1, output);
			}

			fclose(output);

			/* provide warning to user if written file doesn't match checksum */

			image_checksum = 0x10000 - image_checksum;

			if (image_checksum != header.checksum)
				printf("WARNING: checksum of file (%04x) does not match header\n", image_checksum);
		}
	}

	fclose(input);

	return 0;
}

