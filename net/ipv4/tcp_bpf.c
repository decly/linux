// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017 - 2018 Covalent IO, Inc. http://covalent.io */

#include <linux/skmsg.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/util_macros.h>

#include <net/inet_common.h>
#include <net/tls.h>

void tcp_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tcp;
	int copied;

	if (!skb || !skb->len || !sk_is_tcp(sk))
		return;

	if (skb_bpf_strparser(skb))
		return;

	tcp = tcp_sk(sk);
	copied = tcp->copied_seq + skb->len;
	WRITE_ONCE(tcp->copied_seq, copied);
	tcp_rcv_space_adjust(sk);
	__tcp_cleanup_rbuf(sk, skb->len);
}

static int bpf_tcp_ingress(struct sock *sk, struct sk_psock *psock,
			   struct sk_msg *msg, u32 apply_bytes, int flags)
{
	bool apply = apply_bytes;
	struct scatterlist *sge;
	u32 size, copied = 0;
	struct sk_msg *tmp;
	int i, ret = 0;

	tmp = kzalloc(sizeof(*tmp), __GFP_NOWARN | GFP_KERNEL);
	if (unlikely(!tmp))
		return -ENOMEM;

	lock_sock(sk);
	tmp->sg.start = msg->sg.start;
	i = msg->sg.start;
	do {
		sge = sk_msg_elem(msg, i);
		size = (apply && apply_bytes < sge->length) ?
			apply_bytes : sge->length;
		if (!sk_wmem_schedule(sk, size)) {
			if (!copied)
				ret = -ENOMEM;
			break;
		}

		sk_mem_charge(sk, size);
		sk_msg_xfer(tmp, msg, i, size);
		copied += size;
		if (sge->length)
			get_page(sk_msg_page(tmp, i));
		sk_msg_iter_var_next(i);
		tmp->sg.end = i;
		if (apply) {
			apply_bytes -= size;
			if (!apply_bytes) {
				if (sge->length)
					sk_msg_iter_var_prev(i);
				break;
			}
		}
	} while (i != msg->sg.end);

	if (!ret) {
		msg->sg.start = i;
		sk_psock_queue_msg(psock, tmp); /* 加入psock的ingress_msg接收队列 */
		sk_psock_data_ready(sk, psock); /* 唤醒应用层接收 */
	} else {
		sk_msg_free(sk, tmp);
		kfree(tmp);
	}

	release_sock(sk);
	return ret;
}

static int tcp_bpf_push(struct sock *sk, struct sk_msg *msg, u32 apply_bytes,
			int flags, bool uncharge)
{
	struct msghdr msghdr = {};
	bool apply = apply_bytes;
	struct scatterlist *sge;
	struct page *page;
	int size, ret = 0;
	u32 off;

	while (1) {
		struct bio_vec bvec;
		bool has_tx_ulp;

		sge = sk_msg_elem(msg, msg->sg.start);
		size = (apply && apply_bytes < sge->length) ?
			apply_bytes : sge->length;
		off  = sge->offset;
		page = sg_page(sge);

		tcp_rate_check_app_limited(sk);
retry:
		msghdr.msg_flags = flags | MSG_SPLICE_PAGES;
		has_tx_ulp = tls_sw_has_ctx_tx(sk);
		if (has_tx_ulp)
			msghdr.msg_flags |= MSG_SENDPAGE_NOPOLICY;

		if (size < sge->length && msg->sg.start != msg->sg.end)
			msghdr.msg_flags |= MSG_MORE;

		bvec_set_page(&bvec, page, size, off);
		iov_iter_bvec(&msghdr.msg_iter, ITER_SOURCE, &bvec, 1, size);
		ret = tcp_sendmsg_locked(sk, &msghdr, size);
		if (ret <= 0)
			return ret;

		if (apply)
			apply_bytes -= ret;
		msg->sg.size -= ret;
		sge->offset += ret;
		sge->length -= ret;
		if (uncharge)
			sk_mem_uncharge(sk, ret);
		if (ret != size) {
			size -= ret;
			off  += ret;
			goto retry;
		}
		if (!sge->length) {
			put_page(page);
			sk_msg_iter_next(msg, start);
			sg_init_table(sge, 1);
			if (msg->sg.start == msg->sg.end)
				break;
		}
		if (apply && !apply_bytes)
			break;
	}

	return 0;
}

static int tcp_bpf_push_locked(struct sock *sk, struct sk_msg *msg,
			       u32 apply_bytes, int flags, bool uncharge)
{
	int ret;

	lock_sock(sk);
	ret = tcp_bpf_push(sk, msg, apply_bytes, flags, uncharge);
	release_sock(sk);
	return ret;
}

int tcp_bpf_sendmsg_redir(struct sock *sk, bool ingress,
			  struct sk_msg *msg, u32 bytes, int flags)
{
	struct sk_psock *psock = sk_psock_get(sk);
	int ret;

	if (unlikely(!psock))
		return -EPIPE;

	ret = ingress ? bpf_tcp_ingress(sk, psock, msg, bytes, flags) : /* 由sock接收 */
			tcp_bpf_push_locked(sk, msg, bytes, flags, false); /* 由sock发送 */
	sk_psock_put(sk, psock);
	return ret;
}
EXPORT_SYMBOL_GPL(tcp_bpf_sendmsg_redir);

#ifdef CONFIG_BPF_SYSCALL
static int tcp_msg_wait_data(struct sock *sk, struct sk_psock *psock,
			     long timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret = 0;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		return 1;

	if (!timeo)
		return ret;

	add_wait_queue(sk_sleep(sk), &wait);
	sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	ret = sk_wait_event(sk, &timeo,
			    !list_empty(&psock->ingress_msg) ||
			    !skb_queue_empty_lockless(&sk->sk_receive_queue), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
	return ret;
}

static bool is_next_msg_fin(struct sk_psock *psock)
{
	struct scatterlist *sge;
	struct sk_msg *msg_rx;
	int i;

	msg_rx = sk_psock_peek_msg(psock);
	i = msg_rx->sg.start;
	sge = sk_msg_elem(msg_rx, i);
	if (!sge->length) {
		struct sk_buff *skb = msg_rx->skb;

		if (skb && TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			return true;
	}
	return false;
}

/* 接收重定向(即使用了stream_verdict/skb_verdict)的接收函数(也包括同时也使用msg_parser)
 * 与tcp_bpf_recvmsg()的区别是: 本函数只会从psock->ingress_msg中读取数据(也会更新tp->copied_seq),
 * 但不会读取sk->sk_receive_queue
 *
 * 这是因为 commit c5d2177a72a16 中提到的: 应用层recv()可能与bpf程序在sk_receive_queue上竞争
 *
 *       AppB
 *       recv()                (userspace)
 *     -----------------------
 *       tcp_bpf_recvmsg()     (kernel)
 *         |             |
 *         |             |
 *         |             |
 *       ingress_msgQ    |
 *         |             |
 *       RX_BPF          |
 *         |             |
 *         v             v
 *       sk->receive_queue
 *
 * tcp_bpf_recvmsg()会先从ingress_msg中读取, 没有的话则读取sk_receive_queue,
 * 但是在接收重定向中, 数据是先保存到sk_receive_queue, 然后调用bpf程序来处理的
 * (__SK_PASS保存到自身psock->ingress_msg, 而__SK_REDIRECT则会发往其他sock)
 * 这样会出问题: 如果应用层频繁调用recv(), 那么会从sk_receive_queue中读取走还未经过
 * bpf程序处理的数据.
 * 所以, 这里只能读取经过bpf程序处理后的ingress_msg队列, 不能去读取sk_receive_queue队列
 */
static int tcp_bpf_recvmsg_parser(struct sock *sk,
				  struct msghdr *msg,
				  size_t len,
				  int flags,
				  int *addr_len)
{
	struct tcp_sock *tcp = tcp_sk(sk);
	int peek = flags & MSG_PEEK;
	u32 seq = tcp->copied_seq;
	struct sk_psock *psock;
	int copied = 0;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	if (!len)
		return 0;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return tcp_recvmsg(sk, msg, len, flags, addr_len);

	lock_sock(sk);

	/* We may have received data on the sk_receive_queue pre-accept and
	 * then we can not use read_skb in this context because we haven't
	 * assigned a sk_socket yet so have no link to the ops. The work-around
	 * is to check the sk_receive_queue and in these cases read skbs off
	 * queue again. The read_skb hook is not running at this point because
	 * of lock_sock so we avoid having multiple runners in read_skb.
	 */
	if (unlikely(!skb_queue_empty(&sk->sk_receive_queue))) {
		tcp_data_ready(sk);
		/* This handles the ENOMEM errors if we both receive data
		 * pre accept and are already under memory pressure. At least
		 * let user know to retry.
		 */
		if (unlikely(!skb_queue_empty(&sk->sk_receive_queue))) {
			copied = -EAGAIN;
			goto out;
		}
	}

msg_bytes_ready:
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	/* The typical case for EFAULT is the socket was gracefully
	 * shutdown with a FIN pkt. So check here the other case is
	 * some error on copy_page_to_iter which would be unexpected.
	 * On fin return correct return code to zero.
	 */
	if (copied == -EFAULT) {
		bool is_fin = is_next_msg_fin(psock);

		if (is_fin) {
			copied = 0;
			seq++;
			goto out;
		}
	}
	seq += copied;
	if (!copied) {
		long timeo;
		int data;

		if (sock_flag(sk, SOCK_DONE))
			goto out;

		if (sk->sk_err) {
			copied = sock_error(sk);
			goto out;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			goto out;

		if (sk->sk_state == TCP_CLOSE) {
			copied = -ENOTCONN;
			goto out;
		}

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		if (!timeo) {
			copied = -EAGAIN;
			goto out;
		}

		if (signal_pending(current)) {
			copied = sock_intr_errno(timeo);
			goto out;
		}

		data = tcp_msg_wait_data(sk, psock, timeo);
		if (data < 0) {
			copied = data;
			goto unlock;
		}
		if (data && !sk_psock_queue_empty(psock))
			goto msg_bytes_ready;
		copied = -EAGAIN;
	}
out:
	if (!peek)
		WRITE_ONCE(tcp->copied_seq, seq);
	tcp_rcv_space_adjust(sk);
	if (copied > 0)
		__tcp_cleanup_rbuf(sk, copied);

unlock:
	release_sock(sk);
	sk_psock_put(sk, psock);
	return copied;
}

/* 发送重定向(即只使用msg_parser)的接收函数(接收重定向使用的是tcp_bpf_recvmsg_parser)
 * 优先从psock->ingress_msg中接收数据, 没有的话从sk->sk_receive_queue中接收数据
 *
 * 另外, 发送重定向接收是不更新tp->copied_seq的, 因为重定向是直接排队到目标psock->ingress_msg中的,
 * 数据没有先进入sk->sk_receive_queue中(也就没有更新tp->rcv_nxt), 所以对应的接收时也不应该增加copied_seq
 */
static int tcp_bpf_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			   int flags, int *addr_len)
{
	struct sk_psock *psock;
	int copied, ret;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	if (!len)
		return 0;

	psock = sk_psock_get(sk);
	if (unlikely(!psock)) /* 无psock直接调用tcp_recvmsg */
		return tcp_recvmsg(sk, msg, len, flags, addr_len);
	/* 如果sk接收队列sk_receive_queue有数据但psock的接收队列ingress_msg为空
	 * 那么调用tcp_recvmsg来接收sk_receive_queue.
	 */
	if (!skb_queue_empty(&sk->sk_receive_queue) &&
	    sk_psock_queue_empty(psock)) {
		sk_psock_put(sk, psock);
		return tcp_recvmsg(sk, msg, len, flags, addr_len);
	}
	lock_sock(sk);
msg_bytes_ready:
	/* 从psock->ingress_msg获取数据接收到msg */
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	if (!copied) {
		long timeo;
		int data;

		timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
		data = tcp_msg_wait_data(sk, psock, timeo); /* 阻塞的话就等待数据 */
		if (data < 0) {
			ret = data;
			goto unlock;
		}
		if (data) {
			/* psock->ingress_msg接收队列非空则继续接收 */
			if (!sk_psock_queue_empty(psock))
				goto msg_bytes_ready;
			release_sock(sk);
			sk_psock_put(sk, psock);
			/* 否则由tcp_recvmsg来接收sk_receive_queue */
			return tcp_recvmsg(sk, msg, len, flags, addr_len);
		}
		copied = -EAGAIN;
	}
	ret = copied;

unlock:
	release_sock(sk);
	sk_psock_put(sk, psock);
	return ret;
}

static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
				struct sk_msg *msg, int *copied, int flags)
{
	bool cork = false, enospc = sk_msg_full(msg), redir_ingress;
	struct sock *sk_redir;
	u32 tosend, origsize, sent, delta = 0;
	u32 eval;
	int ret;

more_data:
	/* 需要调用msg_parser prog时会置为__SK_NONE
	 * 如果使用了bpf_msg_apply_bytes(), 那么会对接下来apply_bytes大小的数据应用之前的msg_parser prog返回的结果
	 * 所以不需要每次调用msg_parser prog
	 */
	if (psock->eval == __SK_NONE) {
		/* Track delta in msg size to add/subtract it on SK_DROP from
		 * returned to user copied size. This ensures user doesn't
		 * get a positive return code with msg_cut_data and SK_DROP
		 * verdict.
		 */
		delta = msg->sg.size;
		psock->eval = sk_psock_msg_verdict(sk, psock, msg); /* 执行msg_parser prog */
		delta -= msg->sg.size;
	}

	/* 如果在msg_parser prog中调用bpf_msg_cork_bytes()对msg设置了cork_bytes,
	 * 表示msg的数据量太小, 不足以判断数据如何重定向,
	 * 需要等待累计cork_bytes字节的数据才调用msg_parser prog再次判断(由tcp_bpf_sendmsg()跳过本函数).
	 * 注意: 这里没有执行数据发送或重定向直接返回了, 也就是本次msg_parser prog结果是忽略的
	 */
	if (msg->cork_bytes &&
	    msg->cork_bytes > msg->sg.size && !enospc) {
		psock->cork_bytes = msg->cork_bytes - msg->sg.size; /* 将还需要累计的量赋值给psock */
		if (!psock->cork) { /* 分配cork保存缓存的msg */
			psock->cork = kzalloc(sizeof(*psock->cork),
					      GFP_ATOMIC | __GFP_NOWARN);
			if (!psock->cork)
				return -ENOMEM;
		}
		memcpy(psock->cork, msg, sizeof(*msg));
		return 0; /* 直接返回了, 没有对数据进行发送 */
	}

	tosend = msg->sg.size; /* 要发送的大小 */
	/* 如果设置了apply_bytes(bpf_msg_apply_bytes()接口设置), 那么本次发送不能超过apply_bytes */
	if (psock->apply_bytes && psock->apply_bytes < tosend)
		tosend = psock->apply_bytes;
	eval = __SK_NONE;

	switch (psock->eval) { /* 根据msg_parser prog返回结果处理 */
	case __SK_PASS: /* 不进行重定向, 即按照原tcp发送即可 */
		ret = tcp_bpf_push(sk, msg, tosend, flags, true);
		if (unlikely(ret)) {
			*copied -= sk_msg_free(sk, msg);
			break;
		}
		sk_msg_apply_bytes(psock, tosend); /* 更新apply_bytes */
		break;
	case __SK_REDIRECT: /* 需要重定向到其他sock */
		redir_ingress = psock->redir_ingress;
		sk_redir = psock->sk_redir; /* 目的sock */
		sk_msg_apply_bytes(psock, tosend); /* 更新apply_bytes */
		if (!psock->apply_bytes) { /* apply_bytes发完了 */
			/* Clean up before releasing the sock lock. */
			eval = psock->eval;
			psock->eval = __SK_NONE; /* 需要调用msg_parser prog了 */
			psock->sk_redir = NULL;
		}
		if (psock->cork) { /* 直接重定向后需要清空cork */
			cork = true;
			psock->cork = NULL;
		}
		sk_msg_return(sk, msg, tosend);
		release_sock(sk);

		origsize = msg->sg.size;
		/* 重定向数据到sk_redir, 根据BPF_F_INGRESS标志由该sk接受或发送 */
		ret = tcp_bpf_sendmsg_redir(sk_redir, redir_ingress,
					    msg, tosend, flags);
		sent = origsize - msg->sg.size;

		if (eval == __SK_REDIRECT)
			sock_put(sk_redir);

		lock_sock(sk);
		if (unlikely(ret < 0)) {
			int free = sk_msg_free_nocharge(sk, msg);

			if (!cork)
				*copied -= free;
		}
		if (cork) {
			sk_msg_free(sk, msg);
			kfree(msg);
			msg = NULL;
			ret = 0;
		}
		break;
	case __SK_DROP: /* 丢弃 */
	default:
		sk_msg_free_partial(sk, msg, tosend);
		sk_msg_apply_bytes(psock, tosend);
		*copied -= (tosend + delta);
		return -EACCES;
	}

	if (likely(!ret)) {
		if (!psock->apply_bytes) { /* 当apply_bytes发完后才需要再次调用msg_parser */
			psock->eval =  __SK_NONE; /* 再次调用msg_parser prog */
			if (psock->sk_redir) { /* 清除重定向sock */
				sock_put(psock->sk_redir);
				psock->sk_redir = NULL;
			}
		}
		if (msg &&
		    msg->sg.data[msg->sg.start].page_link &&
		    msg->sg.data[msg->sg.start].length) {
			if (eval == __SK_REDIRECT)
				sk_mem_charge(sk, tosend - sent);
			goto more_data; /* 还有数据, 继续执行 */
		}
	}
	return ret;
}

static int tcp_bpf_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sk_msg tmp, *msg_tx = NULL;
	int copied = 0, err = 0;
	struct sk_psock *psock;
	long timeo;
	int flags;

	/* Don't let internal flags through */
	flags = (msg->msg_flags & ~MSG_SENDPAGE_DECRYPTED);
	flags |= MSG_NO_SHARED_FRAGS;

	psock = sk_psock_get(sk); /* 获取保存在sk->sk_user_data的psock */
	if (unlikely(!psock))
		return tcp_sendmsg(sk, msg, size);

	lock_sock(sk);
	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	while (msg_data_left(msg)) { /* 处理要发送的msg */
		bool enospc = false;
		u32 copy, osize;

		if (sk->sk_err) {
			err = -sk->sk_err;
			goto out_err;
		}

		copy = msg_data_left(msg);
		if (!sk_stream_memory_free(sk)) /* 发送缓存满, 等待 */
			goto wait_for_sndbuf;
		if (psock->cork) { /* 如果设置了cork_bytes, 那么获取上次缓存的msg */
			msg_tx = psock->cork;
		} else {
			msg_tx = &tmp;
			sk_msg_init(msg_tx);
		}

		osize = msg_tx->sg.size;
		err = sk_msg_alloc(sk, msg_tx, msg_tx->sg.size + copy, msg_tx->sg.end - 1);
		if (err) {
			if (err != -ENOSPC)
				goto wait_for_memory;
			enospc = true;
			copy = msg_tx->sg.size - osize;
		}

		err = sk_msg_memcopy_from_iter(sk, &msg->msg_iter, msg_tx,
					       copy);
		if (err < 0) {
			sk_msg_trim(sk, msg_tx, osize);
			goto out_err;
		}

		copied += copy;
		/* 如果设置了cork_bytes(bpf_msg_cork_bytes设置),
		 * 需要等待累计cork_bytes字节的数据才调用msg_parser prog
		 * 否则先掉到out_err返回等到下次sendmsg
		 */
		if (psock->cork_bytes) {
			/* 更新下还需要等待的cork_bytes */
			if (size > psock->cork_bytes)
				psock->cork_bytes = 0;
			else
				psock->cork_bytes -= size;
			/* 数据量还未达到(cork_bytes不为0), 直接返回, 也就是不调用msg_parser prog */
			if (psock->cork_bytes && !enospc)
				goto out_err;
			/* All cork bytes are accounted, rerun the prog. */
			/* 这里说明可以调用msg_parser prog了 */
			psock->eval = __SK_NONE;
			psock->cork_bytes = 0;
		}

		/* 核心函数, 执行msg_parser prog并根据结果重定向 */
		err = tcp_bpf_send_verdict(sk, psock, msg_tx, &copied, flags);
		if (unlikely(err < 0))
			goto out_err;
		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		err = sk_stream_wait_memory(sk, &timeo);
		if (err) {
			if (msg_tx && msg_tx != psock->cork)
				sk_msg_free(sk, msg_tx);
			goto out_err;
		}
	}
out_err:
	if (err < 0)
		err = sk_stream_error(sk, msg->msg_flags, err);
	release_sock(sk);
	sk_psock_put(sk, psock);
	return copied ? copied : err;
}

enum {
	TCP_BPF_IPV4,
	TCP_BPF_IPV6,
	TCP_BPF_NUM_PROTS,
};

enum {
	TCP_BPF_BASE,		/* 基础 */
	TCP_BPF_TX,		/* 只发送重定向(msg_parser) */
	TCP_BPF_RX,		/* 只接收重定向(stream_parser/skb_verdict) */
	TCP_BPF_TXRX,		/* 同时使用了发送重定向和接收重定向 */
	TCP_BPF_NUM_CFGS,
};

static struct proto *tcpv6_prot_saved __read_mostly;
static DEFINE_SPINLOCK(tcpv6_prot_lock);
static struct proto tcp_bpf_prots[TCP_BPF_NUM_PROTS][TCP_BPF_NUM_CFGS];

static void tcp_bpf_rebuild_protos(struct proto prot[TCP_BPF_NUM_CFGS],
				   struct proto *base)
{
	/* BASE, 下面的TX,RX,TXRX都会基于此 */
	prot[TCP_BPF_BASE]			= *base; 		/* 先复制tcp_prot */
	prot[TCP_BPF_BASE].destroy		= sock_map_destroy;
	prot[TCP_BPF_BASE].close		= sock_map_close;	/* 释放操作以及将sock从sockmap中删除 */
	prot[TCP_BPF_BASE].recvmsg		= tcp_bpf_recvmsg; 	/* 发送重定向的接收函数 */
	prot[TCP_BPF_BASE].sock_is_readable	= sk_msg_is_readable;

	/* TX: 只使用发送重定向msg_parser(BPF_PROG_TYPE_SK_MSG), 需要修改sendmsg(重定向发送)和recvmsg接口(重定向后的接收) */
	prot[TCP_BPF_TX]			= prot[TCP_BPF_BASE];		/* 基于TCP_BPF_BASE */
	prot[TCP_BPF_TX].sendmsg		= tcp_bpf_sendmsg;		/* 用于msg_parser处理发送重定向 */

	/* RX: 只使用接收重定向stream_verdict/skb_verdict(BPF_PROG_TYPE_SK_SKB), 修改recvmsg接口 */
	prot[TCP_BPF_RX]			= prot[TCP_BPF_BASE];		/* 基于TCP_BPF_BASE */
	prot[TCP_BPF_RX].recvmsg		= tcp_bpf_recvmsg_parser;	/* 使用接收重定向的接收函数 */

	/* TXRX: 同时使用了接收重定向(stream_verdict/skb_verdict)和发送重定向(msg_parser) */
	prot[TCP_BPF_TXRX]			= prot[TCP_BPF_TX];		/* 基于TCP_BPF_TX */
	prot[TCP_BPF_TXRX].recvmsg		= tcp_bpf_recvmsg_parser; 	/* 使用接收重定向的接收函数 */
}

static void tcp_bpf_check_v6_needs_rebuild(struct proto *ops)
{
	if (unlikely(ops != smp_load_acquire(&tcpv6_prot_saved))) {
		spin_lock_bh(&tcpv6_prot_lock);
		if (likely(ops != tcpv6_prot_saved)) {
			tcp_bpf_rebuild_protos(tcp_bpf_prots[TCP_BPF_IPV6], ops);
			smp_store_release(&tcpv6_prot_saved, ops);
		}
		spin_unlock_bh(&tcpv6_prot_lock);
	}
}

static int __init tcp_bpf_v4_build_proto(void)
{
	tcp_bpf_rebuild_protos(tcp_bpf_prots[TCP_BPF_IPV4], &tcp_prot);
	return 0;
}
late_initcall(tcp_bpf_v4_build_proto);

static int tcp_bpf_assert_proto_ops(struct proto *ops)
{
	/* In order to avoid retpoline, we make assumptions when we call
	 * into ops if e.g. a psock is not present. Make sure they are
	 * indeed valid assumptions.
	 */
	return ops->recvmsg  == tcp_recvmsg &&
	       ops->sendmsg  == tcp_sendmsg ? 0 : -ENOTSUPP;
}

int tcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
	int family = sk->sk_family == AF_INET6 ? TCP_BPF_IPV6 : TCP_BPF_IPV4;
	int config = psock->progs.msg_parser   ? TCP_BPF_TX   : TCP_BPF_BASE;

	/* config的取值:
	 * - TCP_BPF_TX, 只使用发送重定向(msg_parser)
	 * - TCP_BPF_RX, 只接收重定向(stream_verdict或skb_verdict)
	 * - TCP_BPF_TXRX, 同时使用发送重定向(msg_parser)和接收重定向(stream_verdict或skb_verdict)
	 */
	if (psock->progs.stream_verdict || psock->progs.skb_verdict) {
		config = (config == TCP_BPF_TX) ? TCP_BPF_TXRX : TCP_BPF_RX;
	}

	if (restore) { /* 置1为恢复还原 */
		if (inet_csk_has_ulp(sk)) {
			/* TLS does not have an unhash proto in SW cases,
			 * but we need to ensure we stop using the sock_map
			 * unhash routine because the associated psock is being
			 * removed. So use the original unhash handler.
			 */
			WRITE_ONCE(sk->sk_prot->unhash, psock->saved_unhash);
			tcp_update_ulp(sk, psock->sk_proto, psock->saved_write_space);
		} else {
			sk->sk_write_space = psock->saved_write_space;
			/* Pairs with lockless read in sk_clone_lock() */
			/* 将协议还原为tcp_prot */
			sock_replace_proto(sk, psock->sk_proto);
		}
		return 0;
	}

	if (sk->sk_family == AF_INET6) {
		if (tcp_bpf_assert_proto_ops(psock->sk_proto))
			return -EINVAL;

		tcp_bpf_check_v6_needs_rebuild(psock->sk_proto);
	}

	/* Pairs with lockless read in sk_clone_lock() */
	/* 将sk的协议替换成tcp_bpf_prots[family][config]
	 * tcp_bpf_prots更改了tcp_prot的几个函数, 见tcp_bpf_rebuild_protos()
	 */
	sock_replace_proto(sk, &tcp_bpf_prots[family][config]);
	return 0;
}
EXPORT_SYMBOL_GPL(tcp_bpf_update_proto);

/* If a child got cloned from a listening socket that had tcp_bpf
 * protocol callbacks installed, we need to restore the callbacks to
 * the default ones because the child does not inherit the psock state
 * that tcp_bpf callbacks expect.
 */
void tcp_bpf_clone(const struct sock *sk, struct sock *newsk)
{
	struct proto *prot = newsk->sk_prot;

	if (is_insidevar(prot, tcp_bpf_prots))
		newsk->sk_prot = sk->sk_prot_creator;
}
#endif /* CONFIG_BPF_SYSCALL */
