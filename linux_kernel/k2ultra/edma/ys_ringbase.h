/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _YS_RINGBASE_H
#define _YS_RINGBASE_H

#include <linux/types.h>
#include <linux/kernel.h>

struct ys_ringbase {
	u16 head;
	u16 tail;
	u16 size;
	u16 mask;
};

static inline void ys_ringb_init(struct ys_ringbase *ring, u16 size)
{
	ring->head = 0;
	ring->tail = 0;
	ring->size = size;
	ring->mask = size - 1;
}

static inline u16 ys_ringb_head(struct ys_ringbase *ring)
{
	return READ_ONCE(ring->head) & ring->mask;
}

static inline u16 ys_ringb_head_orig(struct ys_ringbase *ring)
{
	return READ_ONCE(ring->head);
}

static inline u16 ys_ringb_tail(struct ys_ringbase *ring)
{
	return READ_ONCE(ring->tail) & ring->mask;
}

static inline u16 ys_ringb_tail_orig(struct ys_ringbase *ring)
{
	return READ_ONCE(ring->tail);
}

static inline u16 ys_ringb_size(struct ys_ringbase *ring)
{
	return ring->size;
}

static inline void ys_ringb_push(struct ys_ringbase *ring)
{
	//ring->head++;	/* WRITE_ONCE ?? */
	WRITE_ONCE(ring->head, ys_ringb_head_orig(ring) + 1);
}

static inline void ys_ringb_push_multi(struct ys_ringbase *ring, u16 count)
{
	//ring->head += count;
	WRITE_ONCE(ring->head, ys_ringb_head_orig(ring) + count);
}

static inline void ys_ringb_pop(struct ys_ringbase *ring)
{
	//ring->tail++;
	WRITE_ONCE(ring->tail, ys_ringb_tail_orig(ring) + 1);
}

static inline void ys_ringb_pop_multi(struct ys_ringbase *ring, u16 count)
{
	//ring->tail += count;
	WRITE_ONCE(ring->tail, ys_ringb_tail_orig(ring) + count);
}

static inline bool ys_ringb_empty(struct ys_ringbase *ring)
{
	return ys_ringb_head_orig(ring) == ys_ringb_tail_orig(ring);
}

static inline u16 ys_ringb_used(struct ys_ringbase *ring)
{
	return READ_ONCE(ring->head) - READ_ONCE(ring->tail);
}

static inline u16 ys_ringb_left(struct ys_ringbase *ring)
{
	return (ring->size - ys_ringb_used(ring));
}

static inline u16 ys_ringb_bottom_left(struct ys_ringbase *ring)
{
	return min_t(u16, ring->size - ys_ringb_head(ring), ys_ringb_left(ring));
}

static inline bool ys_ringb_in_bottom(struct ys_ringbase *ring)
{
	return ys_ringb_head(ring) == (ring->size - ys_ringb_bottom_left(ring));
}

static inline u16 ys_ringb_top_left(struct ys_ringbase *ring)
{
	return (u16)(ys_ringb_left(ring) - ys_ringb_bottom_left(ring));
}

#endif /* _YS_RINGBASE_H */

