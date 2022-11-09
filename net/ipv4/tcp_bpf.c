// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017 - 2018 Covalent IO, Inc. http://covalent.io */

#include <linux/skmsg.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/wait.h>

#include <net/inet_common.h>
#include <net/tls.h>

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
			if (!apply_bytes)
				break;
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
	bool apply = apply_bytes;
	struct scatterlist *sge;
	struct page *page;
	int size, ret = 0;
	u32 off;

	while (1) {
		bool has_tx_ulp;

		sge = sk_msg_elem(msg, msg->sg.start);
		size = (apply && apply_bytes < sge->length) ?
			apply_bytes : sge->length;
		off  = sge->offset;
		page = sg_page(sge);

		tcp_rate_check_app_limited(sk);
retry:
		has_tx_ulp = tls_sw_has_ctx_tx(sk);
		if (has_tx_ulp) {
			flags |= MSG_SENDPAGE_NOPOLICY;
			ret = kernel_sendpage_locked(sk,
						     page, off, size, flags);
		} else { /* 调用普通tcp发送 */
			ret = do_tcp_sendpages(sk, page, off, size, flags);
		}

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

int tcp_bpf_sendmsg_redir(struct sock *sk, struct sk_msg *msg,
			  u32 bytes, int flags)
{
	bool ingress = sk_msg_to_ingress(msg); /* 获取BPF_F_INGRESS标志 */
	struct sk_psock *psock = sk_psock_get(sk);
	int ret;

	if (unlikely(!psock)) {
		sk_msg_free(sk, msg);
		return 0;
	}
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
			    !skb_queue_empty(&sk->sk_receive_queue), &wait);
	sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
	remove_wait_queue(sk_sleep(sk), &wait);
	return ret;
}

static int tcp_bpf_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		    int nonblock, int flags, int *addr_len)
{
	struct sk_psock *psock;
	int copied, ret;

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	psock = sk_psock_get(sk);
	if (unlikely(!psock)) /* 无psock直接调用tcp_recvmsg */
		return tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);

	/* 如果sk接收队列sk_receive_queue有数据但psock的接收队列ingress_msg为空
	 * 那么调用tcp_recvmsg来接收sk_receive_queue.
	 */
	if (!skb_queue_empty(&sk->sk_receive_queue) &&
	    sk_psock_queue_empty(psock)) {
		sk_psock_put(sk, psock);
		return tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);
	}
	lock_sock(sk);
msg_bytes_ready:
	/* 从psock->ingress_msg获取数据接收到msg */
	copied = sk_msg_recvmsg(sk, psock, msg, len, flags);
	if (!copied) {
		long timeo;
		int data;

		timeo = sock_rcvtimeo(sk, nonblock);
		data = tcp_msg_wait_data(sk, psock, timeo); /* 阻塞的话就等待数据 */
		if (data) {
			/* psock->ingress_msg接收队列非空则继续接收 */
			if (!sk_psock_queue_empty(psock))
				goto msg_bytes_ready;
			release_sock(sk);
			sk_psock_put(sk, psock);
			/* 否则由tcp_recvmsg来接收sk_receive_queue */
			return tcp_recvmsg(sk, msg, len, nonblock, flags, addr_len);
		}
		copied = -EAGAIN;
	}
	ret = copied;
	release_sock(sk);
	sk_psock_put(sk, psock);
	return ret;
}

static int tcp_bpf_send_verdict(struct sock *sk, struct sk_psock *psock,
				struct sk_msg *msg, int *copied, int flags)
{
	bool cork = false, enospc = sk_msg_full(msg);
	struct sock *sk_redir;
	u32 tosend, delta = 0;
	u32 eval = __SK_NONE;
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

		/* 重定向数据到sk_redir, 根据BPF_F_INGRESS标志由该sk接受或发送 */
		ret = tcp_bpf_sendmsg_redir(sk_redir, msg, tosend, flags);

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
		    msg->sg.data[msg->sg.start].length)
			goto more_data; /* 还有数据, 继续执行 */
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

	/* Don't let internal do_tcp_sendpages() flags through */
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

static int tcp_bpf_sendpage(struct sock *sk, struct page *page, int offset,
			    size_t size, int flags)
{
	struct sk_msg tmp, *msg = NULL;
	int err = 0, copied = 0;
	struct sk_psock *psock;
	bool enospc = false;

	psock = sk_psock_get(sk);
	if (unlikely(!psock))
		return tcp_sendpage(sk, page, offset, size, flags);

	lock_sock(sk);
	if (psock->cork) {
		msg = psock->cork;
	} else {
		msg = &tmp;
		sk_msg_init(msg);
	}

	/* Catch case where ring is full and sendpage is stalled. */
	if (unlikely(sk_msg_full(msg)))
		goto out_err;

	sk_msg_page_add(msg, page, size, offset);
	sk_mem_charge(sk, size);
	copied = size;
	if (sk_msg_full(msg))
		enospc = true;
	if (psock->cork_bytes) {
		if (size > psock->cork_bytes)
			psock->cork_bytes = 0;
		else
			psock->cork_bytes -= size;
		if (psock->cork_bytes && !enospc)
			goto out_err;
		/* All cork bytes are accounted, rerun the prog. */
		psock->eval = __SK_NONE;
		psock->cork_bytes = 0;
	}

	err = tcp_bpf_send_verdict(sk, psock, msg, &copied, flags);
out_err:
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
	TCP_BPF_BASE,
	TCP_BPF_TX,
	TCP_BPF_NUM_CFGS,
};

static struct proto *tcpv6_prot_saved __read_mostly;
static DEFINE_SPINLOCK(tcpv6_prot_lock);
static struct proto tcp_bpf_prots[TCP_BPF_NUM_PROTS][TCP_BPF_NUM_CFGS];

static void tcp_bpf_rebuild_protos(struct proto prot[TCP_BPF_NUM_CFGS],
				   struct proto *base)
{
	/* stream_parser (BPF_PROG_TYPE_SK_SKB)使用, 主要修改接收接口 */
	prot[TCP_BPF_BASE]			= *base; 		/* 先复制tcp_prot */
	prot[TCP_BPF_BASE].unhash		= sock_map_unhash;	/* 释放操作以及将sock从sockmap中删除 */
	prot[TCP_BPF_BASE].close		= sock_map_close;	/* 释放操作以及将sock从sockmap中删除 */
	prot[TCP_BPF_BASE].recvmsg		= tcp_bpf_recvmsg; 	/* 从psock接收数据 */
	prot[TCP_BPF_BASE].sock_is_readable	= sk_msg_is_readable;

	/* msg_parser (BPF_PROG_TYPE_SK_MSG)使用, 在TCP_BPF_BASE基础上增加修改发送接口 */
	prot[TCP_BPF_TX]			= prot[TCP_BPF_BASE];	/* 先复制上面的TCP_BPF_BASE */
	prot[TCP_BPF_TX].sendmsg		= tcp_bpf_sendmsg;	/* 用于msg_parser处理发送重定向 */
	prot[TCP_BPF_TX].sendpage		= tcp_bpf_sendpage;
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
	       ops->sendmsg  == tcp_sendmsg &&
	       ops->sendpage == tcp_sendpage ? 0 : -ENOTSUPP;
}

int tcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore)
{
	int family = sk->sk_family == AF_INET6 ? TCP_BPF_IPV6 : TCP_BPF_IPV4;
	int config = psock->progs.msg_parser   ? TCP_BPF_TX   : TCP_BPF_BASE;

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
			WRITE_ONCE(sk->sk_prot, psock->sk_proto); /* 将协议还原为tcp_prot */
		}
		return 0;
	}

	if (inet_csk_has_ulp(sk))
		return -EINVAL;

	if (sk->sk_family == AF_INET6) {
		if (tcp_bpf_assert_proto_ops(psock->sk_proto))
			return -EINVAL;

		tcp_bpf_check_v6_needs_rebuild(psock->sk_proto);
	}

	/* Pairs with lockless read in sk_clone_lock() */
	/* 将sk的协议替换成tcp_bpf_prots[family][config]
	 * tcp_bpf_prots更改了tcp_prot的几个函数, 见tcp_bpf_rebuild_protos()
	 */
	WRITE_ONCE(sk->sk_prot, &tcp_bpf_prots[family][config]);
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
	int family = sk->sk_family == AF_INET6 ? TCP_BPF_IPV6 : TCP_BPF_IPV4;
	struct proto *prot = newsk->sk_prot;

	if (prot == &tcp_bpf_prots[family][TCP_BPF_BASE])
		newsk->sk_prot = sk->sk_prot_creator;
}
#endif /* CONFIG_BPF_SYSCALL */
