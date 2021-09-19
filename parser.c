#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#define WARN_ON(cond) assert(!cond)
#define round_up(x, y) ((x + (y - 1)) & ~(y - 1))
#define __packed __attribute__((packed))
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define ERR_PTR(err) NULL
#define PTR_ERR(ptr) -EINVAL
#define IS_ERR(ptr) (ptr == NULL)

#define OSSERIALIZE_HDR 0xd3

enum os_otype {
	OS_OTYPE_DICTIONARY = 1,
	OS_OTYPE_ARRAY = 2,
	OS_OTYPE_INT64 = 4,
	OS_OTYPE_STRING = 9,
	OS_OTYPE_BLOB = 10,
	OS_OTYPE_BOOL = 11
};

struct os_tag {
	unsigned int size : 24;
	enum os_otype type : 5;
	unsigned int padding : 2;
	bool last : 1;
} __packed;

#if 0
struct os_object {
	enum os_otype type;
	union {
#endif

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

u32 *parse_u32(struct ctx *ctx)
{
	return parse_bytes(ctx, sizeof(u32));
}

struct os_tag *parse_tag(struct ctx *ctx)
{
	struct os_tag *tag;

	/* Align to 32-bits */
	ctx->pos = round_up(ctx->pos, 4);

	tag = parse_bytes(ctx, sizeof(struct os_tag));
	if (IS_ERR(tag))
		return tag;
	if (tag->padding)
		return ERR_PTR(-EINVAL);
	return tag;
}

struct os_tag *parse_tag_type(struct ctx *ctx, enum os_otype type)
{
	struct os_tag *tag = parse_tag(ctx);
	if (IS_ERR(tag))
		return tag;
	if (tag->type != type)
		return ERR_PTR(-EINVAL);
	return tag;
}

void skip(struct ctx *handle)
{
	struct os_tag *tag = parse_tag(handle);
	if (IS_ERR(tag))
		return;
	switch (tag->type) {
	case OS_OTYPE_DICTIONARY:
		for (int i = 0; i < tag->size; ++i) {
			skip(handle);
			skip(handle);
		}
		break;

	case OS_OTYPE_ARRAY:
		for (int i = 0; i < tag->size; ++i)
			skip(handle);
		break;

	case OS_OTYPE_INT64:
		handle->pos += 8;
		break;
	case OS_OTYPE_STRING:
	case OS_OTYPE_BLOB:
		handle->pos += tag->size;
		break;
	case OS_OTYPE_BOOL:
		break;
	default:
		printf("unknown");
		break;
	}

}

enum os_otype peek_type(struct ctx handle)
{
	struct os_tag *tag = parse_tag(&handle);
	return tag->type;
}

/* Caller must free */
char *parse_string(struct ctx *handle)
{
	struct os_tag *tag = parse_tag_type(handle, OS_OTYPE_STRING);
	const char *in;
	char *out;

	if (IS_ERR(tag))
		return (void *) tag;

	in = parse_bytes(handle, tag->size);
	if (IS_ERR(in))
		return (void *) in;

	out = malloc(tag->size + 1);

	memcpy(out, in, tag->size);
	out[tag->size] = '\0';
	return out;
}

struct dict_iterator {
	struct ctx handle;
	u32 idx;
	u32 len;
};

int dict_iterator_begin(struct ctx dict, struct dict_iterator *it)
{
	struct os_tag *tag;

	*it = (struct dict_iterator) {
		.handle = dict,
		.idx = 0
	};

	tag = parse_tag_type(&it->handle, OS_OTYPE_DICTIONARY);
	if (IS_ERR(tag))
		return PTR_ERR(tag);

	it->len = tag->size;
	return 0;
}

bool dict_iterator_not_done(struct dict_iterator *it)
{
	return it->idx < it->len;
}

void dict_iterator_next(struct dict_iterator *it)
{
	it->idx++;
}

int parse(void *blob, size_t size, struct ctx *ctx)
{
	u32 *header;

	*ctx = (struct ctx) {
		.blob = blob,
		.len = size,
		.pos = 0,
	};

	header = parse_u32(ctx);
	if (IS_ERR(header))
		return PTR_ERR(header);

	if (*header != OSSERIALIZE_HDR)
		return -EINVAL;

	return 0;
}

void print_spaces(int indent) {
	int spaces = indent * 4;
	while(spaces--) putchar(' ');
}

struct ctx print_dict(struct ctx handle, int indent)
{
	struct dict_iterator it;

	printf("{\n");
	for (dict_iterator_begin(handle, &it); dict_iterator_not_done(&it); dict_iterator_next(&it)) {
		char *key = parse_string(&it.handle);
		if (IS_ERR(key))
			return handle;

		print_spaces(indent + 1);
		printf("\"%s\": ", key);
		free(key);

		enum os_otype T = peek_type(it.handle);
		switch (T) {
		case OS_OTYPE_DICTIONARY:
			it.handle = print_dict(it.handle, indent + 1);
			break;

		case OS_OTYPE_ARRAY:
		case OS_OTYPE_INT64:
		case OS_OTYPE_STRING:
		case OS_OTYPE_BLOB:
		case OS_OTYPE_BOOL:
		default:
			skip(&it.handle);
			printf("...");
		}

		printf(",\n");

		//printf("type %u\n", T);
//		char *value = parse_string(&it.handle);
//		if (IS_ERR(value))
//			return 1;
//		printf("%s\n", value);
//		free(value);
	}

	print_spaces(indent);
	printf("}");
	return it.handle;
}

int main(int argc, const char **argv) {
	//FILE *fp = fopen("test.bin", "rb");
	FILE *fp = fopen("attributes.bin", "rb");
	u8 dump[1068];
	fread(dump, 1, sizeof(dump), fp);
	fclose(fp);

	struct ctx handle;

	int ret;
	ret = parse(dump, sizeof(dump), &handle);
	printf("%u\n", ret);

	print_dict(handle, 0);
	return 0;
}
