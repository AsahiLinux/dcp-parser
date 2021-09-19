#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#define round_up(x, y) ((x + (y - 1)) & ~(y - 1))
#define __packed __attribute__((packed))
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define ERR_PTR(err) NULL
#define PTR_ERR(ptr) -EINVAL
#define IS_ERR(ptr) (ptr == NULL)

#define OSSERIALIZE_HDR 0xd3

struct ctx {
	void *blob;
	u32 pos, len;
};

void *parse_bytes(struct ctx *ctx, size_t count)
{
	void *ptr = ctx->blob + ctx->pos;

	if (ctx->pos + count > ctx->len)
		return ERR_PTR(-EINVAL);

	ctx->pos += count;
	return ptr;
}

struct os_tag {
	unsigned int size : 24;
	unsigned int otype : 5;
	unsigned int unk : 2;
	bool last : 1;
} __packed;

u32 *parse_u32(struct ctx *ctx)
{
	return parse_bytes(ctx, sizeof(u32));
}

struct os_tag *parse_tag(struct ctx *ctx)
{
	return parse_bytes(ctx, sizeof(struct os_tag));
}

int parse_obj(struct ctx *ctx)
{
	struct os_tag *tag;

	/* Align to 32-bits */
	ctx->pos = round_up(ctx->pos, 4);

	tag = parse_tag(ctx);
	if (IS_ERR(tag))
		return PTR_ERR(ret);

	printf("Tag: %u %u %u\n", tag->last, tag->otype, tag->size);

	return 0;
}

int parse(void *blob, size_t size)
{
	struct ctx ctx = {
		.blob = blob,
		.len = size,
		.pos = 0,
	};

	u32 *header = parse_u32(&ctx);
	if (IS_ERR(header))
		return PTR_ERR(header);

	if (*header != OSSERIALIZE_HDR)
		return -EINVAL;

	parse_obj(&ctx);

	return 0;
}

int main(int argc, const char **argv) {
	FILE *fp = fopen("test.bin", "rb");
	u8 dump[53];
	fread(dump, 1, sizeof(dump), fp);
	fclose(fp);

	int ret;
	ret = parse(dump, sizeof(dump));
	printf("%u\n", ret);
}
