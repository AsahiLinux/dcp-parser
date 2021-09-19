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
typedef int64_t s64;
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

int skip(struct ctx *handle)
{
	struct os_tag *tag = parse_tag(handle);
	int ret = 0;

	if (IS_ERR(tag))
		return PTR_ERR(tag);

	switch (tag->type) {
	case OS_OTYPE_DICTIONARY:
		for (int i = 0; i < tag->size; ++i) {
			ret |= skip(handle);
			ret |= skip(handle);
		}

		return ret;

	case OS_OTYPE_ARRAY:
		for (int i = 0; i < tag->size; ++i)
			ret |= skip(handle);

		return ret;

	case OS_OTYPE_INT64:
		handle->pos += 8;
		return 0;

	case OS_OTYPE_STRING:
	case OS_OTYPE_BLOB:
		handle->pos += tag->size;
		return 0;

	case OS_OTYPE_BOOL:
		return 0;

	default:
		return -EINVAL;
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

int parse_int64(struct ctx *handle, s64 *value)
{
	void *tag = parse_tag_type(handle, OS_OTYPE_INT64);
	s64 *in;

	if (IS_ERR(tag))
		return PTR_ERR(tag);

	in = parse_bytes(handle, sizeof(s64));

	if (IS_ERR(in))
		return PTR_ERR(in);

	memcpy(value, in, sizeof(*value));
	return 0;
}

int parse_bool(struct ctx *handle, bool *b)
{
	struct os_tag *tag = parse_tag_type(handle, OS_OTYPE_BOOL);
	if (IS_ERR(tag))
		return PTR_ERR(tag);

	*b = !!tag->size;
	return 0;
}

struct iterator {
	struct ctx *handle;
	u32 idx;
	u32 len;
};

int iterator_begin(struct ctx *handle, struct iterator *it, bool dictionary)
{
	struct os_tag *tag;
	enum os_otype type = dictionary ? OS_OTYPE_DICTIONARY : OS_OTYPE_ARRAY;

	*it = (struct iterator) {
		.handle = handle,
		.idx = 0
	};

	tag = parse_tag_type(it->handle, type);
	if (IS_ERR(tag))
		return PTR_ERR(tag);

	it->len = tag->size;
	return 0;
}

#define foreach_in_array(handle, it) \
	for (iterator_begin(handle, &it, false); it.idx < it.len; ++it.idx)
#define foreach_in_dict(handle, it) \
	for (iterator_begin(handle, &it, true); it.idx < it.len; ++it.idx)

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

int print_dict(struct ctx *handle, int indent);
int print_array(struct ctx *handle, int indent);

int print_value(struct ctx *handle, int indent)
{
	int ret;

	switch (peek_type(*handle)) {
	case OS_OTYPE_DICTIONARY:
		return print_dict(handle, indent);

	case OS_OTYPE_ARRAY:
		return print_array(handle, indent);

	case OS_OTYPE_STRING:
	{
		char *val = parse_string(handle);
		if (IS_ERR(val))
			return PTR_ERR(val);

		printf("\"%s\"", val);
		free(val);
		return 0;
	}

	case OS_OTYPE_BOOL:
	{
		bool b;

		ret = parse_bool(handle, &b);
		if (ret)
			return ret;

		printf("%s", b ? "true" : "false");
		return 0;
	}

	case OS_OTYPE_INT64:
	{
		s64 v;

		ret = parse_int64(handle, &v);
		if (ret)
			return ret;

		printf("%ld", v);
		return 0;
	}

	case OS_OTYPE_BLOB:
	{
		skip(handle);
		printf("<blob>");
		return 0;
	}

	default:
		return -EINVAL;
	}
}

int print_dict(struct ctx *handle, int indent)
{
	int ret;
	struct iterator it;

	printf("{\n");
	foreach_in_dict(handle, it) {
		char *key = parse_string(it.handle);
		if (IS_ERR(key))
			return PTR_ERR(key);

		print_spaces(indent + 1);
		printf("\"%s\": ", key);
		free(key);

		ret = print_value(it.handle, indent + 1);
		if (ret)
			return ret;

		printf(",\n");
	}

	print_spaces(indent);
	printf("}");
	return 0;
}

int print_array(struct ctx *handle, int indent)
{
	int ret;
	struct iterator it;

	printf("[\n");
	foreach_in_array(handle, it) {
		print_spaces(indent + 1);

		ret = print_value(it.handle, indent + 1);
		if (ret)
			return ret;

		printf(",\n");
	}

	print_spaces(indent);
	printf("]");
	return 0;
}

struct dimension {
	s64 total, front_porch, sync_width, back_porch, active;
	s64 sync_rate, precise_sync_rate;
};

void print_dimension(struct dimension dim) {
	printf(" (%f)", (float) dim.precise_sync_rate / 65536.0);
}

int parse_dimension(struct ctx *handle, struct dimension *dim)
{
	struct iterator it;
	int ret = 0;

	foreach_in_dict(handle, it) {
		char *key = parse_string(it.handle);

		if (IS_ERR(key))
			return PTR_ERR(handle);

		if (!strcmp(key, "Active"))
			ret = parse_int64(it.handle, &dim->active);
		else if (!strcmp(key, "Total"))
			ret = parse_int64(it.handle, &dim->total);
		else if (!strcmp(key, "FrontPorch"))
			ret = parse_int64(it.handle, &dim->front_porch);
		else if (!strcmp(key, "BackPorch"))
			ret = parse_int64(it.handle, &dim->back_porch);
		else if (!strcmp(key, "SyncWidth"))
			ret = parse_int64(it.handle, &dim->sync_width);
		else if (!strcmp(key, "SyncRate"))
			ret = parse_int64(it.handle, &dim->sync_rate);
		else if (!strcmp(key, "PreciseSyncRate"))
			ret = parse_int64(it.handle, &dim->precise_sync_rate);
		else
			skip(it.handle);

		if (ret)
			return ret;
	}

	return 0;
}

int parse_color_modes(struct ctx *handle, s64 *best_id)
{
	struct iterator outer_it;
	int ret = 0;
	s64 best_score = -1;

	*best_id = -1;

	foreach_in_array(handle, outer_it) {
		struct iterator it;
		s64 score = -1, id = -1;

		foreach_in_dict(handle, it) {
			char *key = parse_string(it.handle);

			if (IS_ERR(key))
				return PTR_ERR(key);

			if (!strcmp(key, "Score"))
				ret = parse_int64(it.handle, &score);
			else if (!strcmp(key, "ID"))
				ret = parse_int64(it.handle, &id);
			else
				skip(it.handle);

			if (ret)
				return ret;
		}

		/* Skip partial entries */
		if (score < 0 || id < 0)
			continue;

		//printf("\t%ld: %ld\n", id, score);
		if (score > best_score) {
			best_score = score;
			*best_id = id;
		}
	}

	return 0;
}



int parse_mode(struct ctx *handle)
{
	int ret = 0;
	struct iterator it;
	struct dimension horiz, vert;
	s64 id = -1;
	s64 best_color_mode = -1;
	bool is_preferred = false;

	foreach_in_dict(handle, it) {
		char *key = parse_string(it.handle);

		if (IS_ERR(key))
			return PTR_ERR(key);

		if (!strcmp(key, "HorizontalAttributes"))
			ret = parse_dimension(it.handle, &horiz);
		else if (!strcmp(key, "VerticalAttributes"))
			ret = parse_dimension(it.handle, &vert);
		else if (!strcmp(key, "ColorModes"))
			ret = parse_color_modes(it.handle, &best_color_mode);
		else if (!strcmp(key, "IsPreferred"))
			ret = parse_bool(it.handle, &is_preferred);
		else if (!strcmp(key, "ID"))
			ret = parse_int64(it.handle, &id);
		else
			skip(it.handle);

		if (ret)
			return ret;
	}

	printf("%ldx%ld", horiz.active, vert.active);
	//print_dimension(horiz);
	print_dimension(vert);
	//printf("\n");
	printf(" ID#%ld, best colour ID#%ld%s\n", id, best_color_mode, is_preferred ? " *" : "");
	return 0;
}

int enumerate_modes(struct ctx *handle)
{
	struct iterator it;
	int ret;

	foreach_in_array(handle, it) {
		ret = parse_mode(it.handle);

		if (ret)
			return ret;
	}

	return 0;
}

int main(int argc, const char **argv) {
	//FILE *fp = fopen("test.bin", "rb");
	//FILE *fp = fopen("attributes.bin", "rb");
	FILE *fp = fopen("timings.bin", "rb");
	u8 dump[196616];
	fread(dump, 1, sizeof(dump), fp);
	fclose(fp);

	struct ctx handle;

	int ret;
	ret = parse(dump, sizeof(dump), &handle);
	printf("%u\n", ret);

	enumerate_modes(&handle);
	//print_value(&handle, 0);
	return 0;
}
