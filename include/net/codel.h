#ifndef __NET_SCHED_CODEL_H
#define __NET_SCHED_CODEL_H

/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>

/* Controlling Queue Delay (CoDel) algorithm
 * =========================================
 * Source : Kathleen Nichols and Van Jacobson
 * http://queue.acm.org/detail.cfm?id=2209336
 *
 * Implemented on linux by Dave Taht and Eric Dumazet
 */


/* CoDel uses a 1024 nsec clock, encoded in u32
 * This gives a range of 2199 seconds, because of signed compares
 */
typedef u32 codel_time_t;
typedef s32 codel_tdiff_t;
#define CODEL_SHIFT 10
#define MS2TIME(a) ((a * NSEC_PER_MSEC) >> CODEL_SHIFT)

static inline codel_time_t codel_get_time(void)
{
	u64 ns = ktime_get_ns();

	return ns >> CODEL_SHIFT;
}

/* Dealing with timer wrapping, according to RFC 1982, as desc in wikipedia:
 *  https://en.wikipedia.org/wiki/Serial_number_arithmetic#General_Solution
 * codel_time_after(a,b) returns true if the time a is after time b.
 */
#define codel_time_after(a, b)						\
	(typecheck(codel_time_t, a) &&					\
	 typecheck(codel_time_t, b) &&					\
	 ((s32)((a) - (b)) > 0))
#define codel_time_before(a, b) 	codel_time_after(b, a)

#define codel_time_after_eq(a, b)					\
	(typecheck(codel_time_t, a) &&					\
	 typecheck(codel_time_t, b) &&					\
	 ((s32)((a) - (b)) >= 0))
#define codel_time_before_eq(a, b)	codel_time_after_eq(b, a)

static inline u32 codel_time_to_us(codel_time_t val)
{
	u64 valns = ((u64)val << CODEL_SHIFT);

	do_div(valns, NSEC_PER_USEC);
	return (u32)valns;
}

/**
 * struct codel_params - contains codel parameters
 * @target:	target queue size (in time units)
 * @ce_threshold:  threshold for marking packets with ECN CE
 * @interval:	width of moving time window
 * @mtu:	device mtu, or minimal queue backlog in bytes.
 * @ecn:	is Explicit Congestion Notification enabled
 * @ce_threshold_selector: apply ce_threshold to packets matching this value
 *                         in the diffserv/ECN byte of the IP header
 * @ce_threshold_mask: mask to apply to ce_threshold_selector comparison
 */
struct codel_params { /* 参数结构体 */
	codel_time_t	target;	/* skb延迟发送时间(enqueue到dequeue的时间差)
				 * 超过target(默认5ms)则认为负载大.
				 * tc参数target可设置.
				 */
	codel_time_t	ce_threshold; /* skb发送时如果延迟时间超过ce_threshold则标记CE,
				       * 默认很大值(大概2147秒), 相当于关闭该功能
				       * tc参数ce_threshold可设置.
				       */
	codel_time_t	interval; /* skb延迟发送时间超过target的持续时间超过interval(默认100ms)时, 该flow进入丢包状态,
				   * 即认为该flow的skb一直处于持续延迟发送的状态;
				   * 注意丢包状态是针对每个flow单独设置的, 不是整个qdisc;
				   * 进入丢包状态后每一个丢包周期(动态)丢弃一个skb或设置CE标记(ecn参数开启, 默认),
				   * 直到获取的skb延迟发送时间小于target才退出丢包状态.
				   * tc参数interval可设置.
				   */
	u32		mtu;	/* 当qdisc缓存的数据包总大小不超过mtu时(默认为mtu大小, 即不超过1个数据包),
				 * 就算延迟持续时间超过interval也不会进入丢包状态
				 */
	bool		ecn;	/* 是否开启ecn标记, 默认开启
				 * 开启后在丢包状态(延迟持续时间超过interval)时标记CE标志而不丢包
				 * tc参数[no]ecn可设置.
				 */
	u8		ce_threshold_selector;
	u8		ce_threshold_mask;
};

/**
 * struct codel_vars - contains codel variables
 * @count:		how many drops we've done since the last time we
 *			entered dropping state
 * @lastcount:		count at entry to dropping state
 * @dropping:		set to true if in dropping state
 * @rec_inv_sqrt:	reciprocal value of sqrt(count) >> 1
 * @first_above_time:	when we went (or will go) continuously above target
 *			for interval
 * @drop_next:		time to drop next packet, or when we dropped last
 * @ldelay:		sojourn time of last dequeued packet
 */
struct codel_vars {
	u32		count;		/* 本次进入丢包状态后丢包的数量 */
	u32		lastcount;
	bool		dropping;	/* 标记进入丢包状态 */
	u16		rec_inv_sqrt;
	codel_time_t	first_above_time; /* 用来辅助判断skb延迟持续时间超过阈值 */
	codel_time_t	drop_next;	/* 表示一个丢包周期, 一个周期丢一个skb */
	codel_time_t	ldelay;		/* skb延迟时间, 即enqueue到dequeue的时间差 */
};

#define REC_INV_SQRT_BITS (8 * sizeof(u16)) /* or sizeof_in_bits(rec_inv_sqrt) */
/* needed shift to get a Q0.32 number from rec_inv_sqrt */
#define REC_INV_SQRT_SHIFT (32 - REC_INV_SQRT_BITS)

/**
 * struct codel_stats - contains codel shared variables and stats
 * @maxpacket:	largest packet we've seen so far
 * @drop_count:	temp count of dropped packets in dequeue()
 * @drop_len:	bytes of dropped packets in dequeue()
 * @ecn_mark:	number of packets we ECN marked instead of dropping
 * @ce_mark:	number of packets CE marked because sojourn time was above ce_threshold
 */
struct codel_stats {
	u32		maxpacket;	/* 见过的最大skb的大小 */
	u32		drop_count;
	u32		drop_len;
	u32		ecn_mark;	/* 延迟发送后进入丢包状态 标记CE代替丢包的数据包个数 */
	u32		ce_mark;	/* 发送延迟时间超过ce_threshold标记CE的数据包个数 */
};

#define CODEL_DISABLED_THRESHOLD INT_MAX

typedef u32 (*codel_skb_len_t)(const struct sk_buff *skb);
typedef codel_time_t (*codel_skb_time_t)(const struct sk_buff *skb);
typedef void (*codel_skb_drop_t)(struct sk_buff *skb, void *ctx);
typedef struct sk_buff * (*codel_skb_dequeue_t)(struct codel_vars *vars,
						void *ctx);

#endif
