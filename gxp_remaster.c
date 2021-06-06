/*
    command-line tool to replace partition in Grandstream GXP firmware image
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

int main(int argc, char *argv[])
{
	struct AES_ctx ctx;
	int index, image_count, i, matching_image_index;
	uint8_t buffer[32];
	FILE *input_fw, *output_fw, *image;
	uint32_t signature = 0;
	long oldfw_size, sum_of_old_image_sizes, header_size, remaining, image_size, sizes_location;
	struct part_header header;
	uint8_t part_key[16];
	uint8_t *pnt;
	uint16_t image_checksum, chksum;
	uint8_t *scratchpad;
	uint32_t tmp;

	if (argc < 4)
	{
		fprintf(stderr, "%s <input_fw> <output_fw> <revised_image>\n", argv[0]);
		return -1;
	}

	/* open output firmware file */

	output_fw = fopen(argv[2], "wb");

	if (!output_fw)
	{
		fprintf(stderr, "ERROR: unable to open %s for writing\n", argv[2]);
		return -1;
	}

	/* open input firmware file and check signature */

	input_fw = fopen(argv[1], "rb");

	if (!input_fw)
	{
		fprintf(stderr, "ERROR: unable to open %s\n", argv[1]);
		return -1;
	}

	fread(&signature, sizeof(signature), 1, input_fw);

	if (MAGIC_SIGNATURE != signature)
	{
		fprintf(stderr, "ERROR: bad signature\n");
		return -1;
	}

	/* obtain input firmware file size (helpful for sanity checking) */

	fseek(input_fw, 0, SEEK_END);
	oldfw_size = ftell(input_fw);
	fseek(input_fw, 4, SEEK_SET);

	/* collect all the filenames */

	image_count = 0;

	for (;;)
	{
		if (sizeof(filenames) / sizeof(*filenames) == image_count)
		{
			fprintf(stderr, "ERROR: too many filenames\n");
			return -1;
		}

		if (!fread(&filenames[image_count], sizeof(*filenames), 1, input_fw))
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

	/* we've reached the end of the filenames and gone one step too far, so we backtrack by one */

	fseek(input_fw, -sizeof(*filenames), SEEK_CUR);
	sizes_location = ftell(input_fw);

	/* read the sizes of each of the images */

	for (index = 0, sum_of_old_image_sizes = 0; index < image_count; index++)
	{
		if (!fread(&sizes[index], sizeof(*sizes), 1, input_fw))
		{
			fprintf(stderr, "ERROR: premature EOF in sizes\n");
			return -1;
		}

		sum_of_old_image_sizes += sizes[index];
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

	/* determine the header size (varies between models) and sanity check it */

	header_size = oldfw_size - sum_of_old_image_sizes;

	if (header_size <= 0)
	{
		fprintf(stderr, "ERROR: unexpected header format\n");
		return -1;
	}

	/* verify that the input image file matches one of the existing ones */

	matching_image_index = -1;
	for (index = 0; index < image_count; index++)
	{
		if (strstr(argv[3], filenames[index]))
		{
			matching_image_index = index;
			goto match_found;
		}
	}

	fprintf(stderr, "provided image file (%s) name doesn't match any found in input firmware\n", argv[3]);
	fclose(input_fw);
	fclose(output_fw);
	return -1;

match_found:

	image = fopen(argv[3], "rb");

	if (!image)
	{
		fprintf(stderr, "ERROR: image file %s could not be opened\n", argv[3]);
		return -1;
	}

	/* obtain file size (helpful for sanity checking) */

	fseek(image, 0, SEEK_END);
	image_size = ftell(image);
	fseek(image, 0, SEEK_SET);

	/* sanity check the size of the provided updated image */

	if (image_size % sizeof(buffer))
	{
		fprintf(stderr, "ERROR: provided image has a size 0x%lx incompatible with the cipher algorithm\n", image_size);
		return -1;
	}

	image_checksum = 0;
	while (fread(buffer, sizeof(buffer), 1, image))
	{
		for (index = 0; index < sizeof(buffer); index += 2)
		{
			chksum = buffer[index + 1];
			chksum <<= 8;
			chksum += buffer[index + 0];
			image_checksum += chksum;
		}
	}

	image_checksum = (0x10000 - image_checksum) & 0xFFFF;

	scratchpad = (uint8_t *)malloc((header_size > 0x200) ? header_size : 0x200);

	if (!scratchpad)
	{
		fprintf(stderr, "ERROR: malloc failure\n");
		return -1;
	}

	/* update file header to reflect new image size */

	fseek(input_fw, 0, SEEK_SET);
	fread(scratchpad, header_size, 1, input_fw);

	tmp = image_size + 0x200;
	memcpy(scratchpad + sizes_location + (4 * matching_image_index), &tmp, sizeof(tmp));

	/* update file header to reflect new version */

	memcpy(&tmp, scratchpad + sizes_location + (4 * 8) + (4 * matching_image_index), sizeof(tmp));
	tmp ^= 1;
	memcpy(scratchpad + sizes_location + (4 * 8) + (4 * matching_image_index), &tmp, sizeof(tmp));

	/* write revised file header to new file */

	fwrite(scratchpad, header_size, 1, output_fw);

	/* iterate through each of the files */

	for (index = 0; index < image_count; index++)
	{
		if (index == matching_image_index)
		{
			/* start at the very beginning, a very good place to start */

			fseek(image, 0, SEEK_SET);

			/* read the image header and decrypt with the default key */

			fread(scratchpad, 0x200, 1, input_fw);

			AES_init_ctx(&ctx, default_key);
			AES_ctx_set_iv(&ctx, iv);
			AES_CBC_decrypt_buffer(&ctx, scratchpad, sizeof(header));
			memcpy(&header, scratchpad, sizeof(header));

			/* update fields */

			header.checksum = image_checksum;
			header.image_size = image_size;
			header.version ^= 1;

			/* the image decryption key is derived from the header and only needs byte swapping */

			pnt = (uint8_t *)&header.id;
			for (i = 0; i < 16; i+=2)
			{
				part_key[i + 0] = pnt[i + 1];
				part_key[i + 1] = pnt[i + 0];
			}

			/* re-encrypt the header and write to the new file */

			memcpy(scratchpad, &header, sizeof(header));
			AES_ctx_set_iv(&ctx, iv);
			AES_CBC_encrypt_buffer(&ctx, scratchpad, sizeof(header));

			fwrite(scratchpad, 0x200, 1, output_fw);

			/* encrypt the new image file and write it to the new file */

			AES_init_ctx(&ctx, part_key);

			for (i = 0; i < image_size; i += sizeof(buffer))
			{
				fread(buffer, sizeof(buffer), 1, image);
				AES_ctx_set_iv(&ctx, iv);
				AES_CBC_encrypt_buffer(&ctx, buffer, sizeof(buffer));

				fwrite(buffer, sizeof(buffer), 1, output_fw);
			}

			/* for the input firmware, skip over the data we didn't use */

			fseek(input_fw, sizes[index] - 0x200, SEEK_CUR);
		}
		else
		{
			/* copy unmodified image as-is */

			for (i = 0; i < sizes[index]; i += sizeof(buffer))
			{
				fread(buffer, sizeof(buffer), 1, input_fw);
				fwrite(buffer, sizeof(buffer), 1, output_fw);
			}
		}
	}

	fclose(input_fw);
	fclose(output_fw);
	fclose(image);

	return 0;
}

