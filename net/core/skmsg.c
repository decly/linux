// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017 - 2018 Covalent IO, Inc. http://covalent.io */

#include <linux/skmsg.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <net/tls.h>

static bool sk_msg_try_coalesce_ok(struct sk_msg *msg, int elem_first_coalesce)
{
	if (msg->sg.end > msg->sg.start &&
	    elem_first_coalesce < msg->sg.end)
		return true;

	if (msg->sg.end < msg->sg.start &&
	    (elem_first_coalesce > msg->sg.start ||
	     elem_first_coalesce < msg->sg.end))
		return true;

	return false;
}

int sk_msg_alloc(struct sock *sk, struct sk_msg *msg, int len,
		 int elem_first_coalesce)
{
	struct page_frag *pfrag = sk_page_frag(sk);
	int ret = 0;

	len -= msg->sg.size;
	while (len > 0) {
		struct scatterlist *sge;
		u32 orig_offset;
		int use, i;

		if (!sk_page_frag_refill(sk, pfrag))
			return -ENOMEM;

		orig_offset = pfrag->offset;
		use = min_t(int, len, pfrag->size - orig_offset);
		if (!sk_wmem_schedule(sk, use))
			return -ENOMEM;

		i = msg->sg.end;
		sk_msg_iter_var_prev(i);
		sge = &msg->sg.data[i];

		if (sk_msg_try_coalesce_ok(msg, elem_first_coalesce) &&
		    sg_page(sge) == pfrag->page &&
		    sge->offset + sge->length == orig_offset) {
			sge->length += use;
		} else {
			if (sk_msg_full(msg)) {
				ret = -ENOSPC;
				break;
			}

			sge = &msg->sg.data[msg->sg.end];
			sg_unmark_end(sge);
			sg_set_page(sge, pfrag->page, use, orig_offset);
			get_page(pfrag->page);
			sk_msg_iter_next(msg, end);
		}

		sk_mem_charge(sk, use);
		msg->sg.size += use;
		pfrag->offset += use;
		len -= use;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sk_msg_alloc);

int sk_msg_clone(struct sock *sk, struct sk_msg *dst, struct sk_msg *src,
		 u32 off, u32 len)
{
	int i = src->sg.start;
	struct scatterlist *sge = sk_msg_elem(src, i);
	struct scatterlist *sgd = NULL;
	u32 sge_len, sge_off;

	while (off) {
		if (sge->length > off)
			break;
		off -= sge->length;
		sk_msg_iter_var_next(i);
		if (i == src->sg.end && off)
			return -ENOSPC;
		sge = sk_msg_elem(src, i);
	}

	while (len) {
		sge_len = sge->length - off;
		if (sge_len > len)
			sge_len = len;

		if (dst->sg.end)
			sgd = sk_msg_elem(dst, dst->sg.end - 1);

		if (sgd &&
		    (sg_page(sge) == sg_page(sgd)) &&
		    (sg_virt(sge) + off == sg_virt(sgd) + sgd->length)) {
			sgd->length += sge_len;
			dst->sg.size += sge_len;
		} else if (!sk_msg_full(dst)) {
			sge_off = sge->offset + off;
			sk_msg_page_add(dst, sg_page(sge), sge_len, sge_off);
		} else {
			return -ENOSPC;
		}

		off = 0;
		len -= sge_len;
		sk_mem_charge(sk, sge_len);
		sk_msg_iter_var_next(i);
		if (i == src->sg.end && len)
			return -ENOSPC;
		sge = sk_msg_elem(src, i);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(sk_msg_clone);

void sk_msg_return_zero(struct sock *sk, struct sk_msg *msg, int bytes)
{
	int i = msg->sg.start;

	do {
		struct scatterlist *sge = sk_msg_elem(msg, i);

		if (bytes < sge->length) {
			sge->length -= bytes;
			sge->offset += bytes;
			sk_mem_uncharge(sk, bytes);
			break;
		}

		sk_mem_uncharge(sk, sge->length);
		bytes -= sge->length;
		sge->length = 0;
		sge->offset = 0;
		sk_msg_iter_var_next(i);
	} while (bytes && i != msg->sg.end);
	msg->sg.start = i;
}
EXPORT_SYMBOL_GPL(sk_msg_return_zero);

void sk_msg_return(struct sock *sk, struct sk_msg *msg, int bytes)
{
	int i = msg->sg.start;

	do {
		struct scatterlist *sge = &msg->sg.data[i];
		int uncharge = (bytes < sge->length) ? bytes : sge->length;

		sk_mem_uncharge(sk, uncharge);
		bytes -= uncharge;
		sk_msg_iter_var_next(i);
	} while (i != msg->sg.end);
}
EXPORT_SYMBOL_GPL(sk_msg_return);

static int sk_msg_free_elem(struct sock *sk, struct sk_msg *msg, u32 i,
			    bool charge)
{
	struct scatterlist *sge = sk_msg_elem(msg, i);
	u32 len = sge->length;

	/* When the skb owns the memory we free it from consume_skb path. */
	if (!msg->skb) {
		if (charge)
			sk_mem_uncharge(sk, len);
		put_page(sg_page(sge));
	}
	memset(sge, 0, sizeof(*sge));
	return len;
}

static int __sk_msg_free(struct sock *sk, struct sk_msg *msg, u32 i,
			 bool charge)
{
	struct scatterlist *sge = sk_msg_elem(msg, i);
	int freed = 0;

	while (msg->sg.size) {
		msg->sg.size -= sge->length;
		freed += sk_msg_free_elem(sk, msg, i, charge);
		sk_msg_iter_var_next(i);
		sk_msg_check_to_free(msg, i, msg->sg.size);
		sge = sk_msg_elem(msg, i);
	}
	consume_skb(msg->skb);
	sk_msg_init(msg);
	return freed;
}

int sk_msg_free_nocharge(struct sock *sk, struct sk_msg *msg)
{
	return __sk_msg_free(sk, msg, msg->sg.start, false);
}
EXPORT_SYMBOL_GPL(sk_msg_free_nocharge);

int sk_msg_free(struct sock *sk, struct sk_msg *msg)
{
	return __sk_msg_free(sk, msg, msg->sg.start, true);
}
EXPORT_SYMBOL_GPL(sk_msg_free);

static void __sk_msg_free_partial(struct sock *sk, struct sk_msg *msg,
				  u32 bytes, bool charge)
{
	struct scatterlist *sge;
	u32 i = msg->sg.start;

	while (bytes) {
		sge = sk_msg_elem(msg, i);
		if (!sge->length)
			break;
		if (bytes < sge->length) {
			if (charge)
				sk_mem_uncharge(sk, bytes);
			sge->length -= bytes;
			sge->offset += bytes;
			msg->sg.size -= bytes;
			break;
		}

		msg->sg.size -= sge->length;
		bytes -= sge->length;
		sk_msg_free_elem(sk, msg, i, charge);
		sk_msg_iter_var_next(i);
		sk_msg_check_to_free(msg, i, bytes);
	}
	msg->sg.start = i;
}

void sk_msg_free_partial(struct sock *sk, struct sk_msg *msg, u32 bytes)
{
	__sk_msg_free_partial(sk, msg, bytes, true);
}
EXPORT_SYMBOL_GPL(sk_msg_free_partial);

void sk_msg_free_partial_nocharge(struct sock *sk, struct sk_msg *msg,
				  u32 bytes)
{
	__sk_msg_free_partial(sk, msg, bytes, false);
}

void sk_msg_trim(struct sock *sk, struct sk_msg *msg, int len)
{
	int trim = msg->sg.size - len;
	u32 i = msg->sg.end;

	if (trim <= 0) {
		WARN_ON(trim < 0);
		return;
	}

	sk_msg_iter_var_prev(i);
	msg->sg.size = len;
	while (msg->sg.data[i].length &&
	       trim >= msg->sg.data[i].length) {
		trim -= msg->sg.data[i].length;
		sk_msg_free_elem(sk, msg, i, true);
		sk_msg_iter_var_prev(i);
		if (!trim)
			goto out;
	}

	msg->sg.data[i].length -= trim;
	sk_mem_uncharge(sk, trim);
	/* Adjust copybreak if it falls into the trimmed part of last buf */
	if (msg->sg.curr == i && msg->sg.copybreak > msg->sg.data[i].length)
		msg->sg.copybreak = msg->sg.data[i].length;
out:
	sk_msg_iter_var_next(i);
	msg->sg.end = i;

	/* If we trim data a full sg elem before curr pointer update
	 * copybreak and current so that any future copy operations
	 * start at new copy location.
	 * However trimed data that has not yet been used in a copy op
	 * does not require an update.
	 */
	if (!msg->sg.size) {
		msg->sg.curr = msg->sg.start;
		msg->sg.copybreak = 0;
	} else if (sk_msg_iter_dist(msg->sg.start, msg->sg.curr) >=
		   sk_msg_iter_dist(msg->sg.start, msg->sg.end)) {
		sk_msg_iter_var_prev(i);
		msg->sg.curr = i;
		msg->sg.copybreak = msg->sg.data[i].length;
	}
}
EXPORT_SYMBOL_GPL(sk_msg_trim);

int sk_msg_zerocopy_from_iter(struct sock *sk, struct iov_iter *from,
			      struct sk_msg *msg, u32 bytes)
{
	int i, maxpages, ret = 0, num_elems = sk_msg_elem_used(msg);
	const int to_max_pages = MAX_MSG_FRAGS;
	struct page *pages[MAX_MSG_FRAGS];
	ssize_t orig, copied, use, offset;

	orig = msg->sg.size;
	while (bytes > 0) {
		i = 0;
		maxpages = to_max_pages - num_elems;
		if (maxpages == 0) {
			ret = -EFAULT;
			goto out;
		}

		copied = iov_iter_get_pages(from, pages, bytes, maxpages,
					    &offset);
		if (copied <= 0) {
			ret = -EFAULT;
			goto out;
		}

		iov_iter_advance(from, copied);
		bytes -= copied;
		msg->sg.size += copied;

		while (copied) {
			use = min_t(int, copied, PAGE_SIZE - offset);
			sg_set_page(&msg->sg.data[msg->sg.end],
				    pages[i], use, offset);
			sg_unmark_end(&msg->sg.data[msg->sg.end]);
			sk_mem_charge(sk, use);

			offset = 0;
			copied -= use;
			sk_msg_iter_next(msg, end);
			num_elems++;
			i++;
		}
		/* When zerocopy is mixed with sk_msg_*copy* operations we
		 * may have a copybreak set in this case clear and prefer
		 * zerocopy remainder when possible.
		 */
		msg->sg.copybreak = 0;
		msg->sg.curr = msg->sg.end;
	}
out:
	/* Revert iov_iter updates, msg will need to use 'trim' later if it
	 * also needs to be cleared.
	 */
	if (ret)
		iov_iter_revert(from, msg->sg.size - orig);
	return ret;
}
EXPORT_SYMBOL_GPL(sk_msg_zerocopy_from_iter);

int sk_msg_memcopy_from_iter(struct sock *sk, struct iov_iter *from,
			     struct sk_msg *msg, u32 bytes)
{
	int ret = -ENOSPC, i = msg->sg.curr;
	struct scatterlist *sge;
	u32 copy, buf_size;
	void *to;

	do {
		sge = sk_msg_elem(msg, i);
		/* This is possible if a trim operation shrunk the buffer */
		if (msg->sg.copybreak >= sge->length) {
			msg->sg.copybreak = 0;
			sk_msg_iter_var_next(i);
			if (i == msg->sg.end)
				break;
			sge = sk_msg_elem(msg, i);
		}

		buf_size = sge->length - msg->sg.copybreak;
		copy = (buf_size > bytes) ? bytes : buf_size;
		to = sg_virt(sge) + msg->sg.copybreak;
		msg->sg.copybreak += copy;
		if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY)
			ret = copy_from_iter_nocache(to, copy, from);
		else
			ret = copy_from_iter(to, copy, from);
		if (ret != copy) {
			ret = -EFAULT;
			goto out;
		}
		bytes -= copy;
		if (!bytes)
			break;
		msg->sg.copybreak = 0;
		sk_msg_iter_var_next(i);
	} while (i != msg->sg.end);
out:
	msg->sg.curr = i;
	return ret;
}
EXPORT_SYMBOL_GPL(sk_msg_memcopy_from_iter);

/* Receive sk_msg from psock->ingress_msg to @msg. */
int sk_msg_recvmsg(struct sock *sk, struct sk_psock *psock, struct msghdr *msg,
		   int len, int flags)
{
	struct iov_iter *iter = &msg->msg_iter;
	int peek = flags & MSG_PEEK;
	struct sk_msg *msg_rx;
	int i, copied = 0;

	msg_rx = sk_psock_peek_msg(psock);
	while (copied != len) {
		struct scatterlist *sge;

		if (unlikely(!msg_rx))
			break;

		i = msg_rx->sg.start;
		do {
			struct page *page;
			int copy;

			sge = sk_msg_elem(msg_rx, i);
			copy = sge->length;
			page = sg_page(sge);
			if (copied + copy > len)
				copy = len - copied;
			copy = copy_page_to_iter(page, sge->offset, copy, iter);
			if (!copy)
				return copied ? copied : -EFAULT;

			copied += copy;
			if (likely(!peek)) {
				sge->offset += copy;
				sge->length -= copy;
				if (!msg_rx->skb)
					sk_mem_uncharge(sk, copy);
				msg_rx->sg.size -= copy;

				if (!sge->length) {
					sk_msg_iter_var_next(i);
					if (!msg_rx->skb)
						put_page(page);
				}
			} else {
				/* Lets not optimize peek case if copy_page_to_iter
				 * didn't copy the entire length lets just break.
				 */
				if (copy != sge->length)
					return copied;
				sk_msg_iter_var_next(i);
			}

			if (copied == len)
				break;
		} while (i != msg_rx->sg.end);

		if (unlikely(peek)) {
			msg_rx = sk_psock_next_msg(psock, msg_rx);
			if (!msg_rx)
				break;
			continue;
		}

		msg_rx->sg.start = i;
		if (!sge->length && msg_rx->sg.start == msg_rx->sg.end) {
			msg_rx = sk_psock_dequeue_msg(psock);
			kfree_sk_msg(msg_rx);
		}
		msg_rx = sk_psock_peek_msg(psock);
	}

	return copied;
}
EXPORT_SYMBOL_GPL(sk_msg_recvmsg);

bool sk_msg_is_readable(struct sock *sk)
{
	struct sk_psock *psock;
	bool empty = true;

	rcu_read_lock();
	psock = sk_psock(sk);
	if (likely(psock))
		empty = list_empty(&psock->ingress_msg);
	rcu_read_unlock();
	return !empty;
}
EXPORT_SYMBOL_GPL(sk_msg_is_readable);

static struct sk_msg *sk_psock_create_ingress_msg(struct sock *sk,
						  struct sk_buff *skb)
{
	struct sk_msg *msg;

	if (atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf)
		return NULL;

	if (!sk_rmem_schedule(sk, skb, skb->truesize))
		return NULL;

	msg = kzalloc(sizeof(*msg), __GFP_NOWARN | GFP_KERNEL);
	if (unlikely(!msg))
		return NULL;

	sk_msg_init(msg);
	return msg;
}

static int sk_psock_skb_ingress_enqueue(struct sk_buff *skb,
					struct sk_psock *psock,
					struct sock *sk,
					struct sk_msg *msg)
{
	int num_sge, copied;

	/* skb linearize may fail with ENOMEM, but lets simply try again
	 * later if this happens. Under memory pressure we don't want to
	 * drop the skb. We need to linearize the skb so that the mapping
	 * in skb_to_sgvec can not error.
	 */
	if (skb_linearize(skb))
		return -EAGAIN;
	num_sge = skb_to_sgvec(skb, msg->sg.data, 0, skb->len);
	if (unlikely(num_sge < 0))
		return num_sge;

	copied = skb->len;
	msg->sg.start = 0;
	msg->sg.size = copied;
	msg->sg.end = num_sge;
	msg->skb = skb;

	sk_psock_queue_msg(psock, msg); /* 加入到psock->ingress_msg */
	sk_psock_data_ready(sk, psock); /* 这里调用原始的sk_data_ready来唤醒应用层接收,
					 * 然后应用层调用recv()时会调用tcp_bpf_recvmsg()
					 * 来从poskc->ingress_msg接收数据
					 */
	return copied;
}

static int sk_psock_skb_ingress_self(struct sk_psock *psock, struct sk_buff *skb);

static int sk_psock_skb_ingress(struct sk_psock *psock, struct sk_buff *skb)
{
	struct sock *sk = psock->sk;
	struct sk_msg *msg;
	int err;

	/* If we are receiving on the same sock skb->sk is already assigned,
	 * skip memory accounting and owner transition seeing it already set
	 * correctly.
	 */
	/* skb->sk是原始接收的sk, 相等说明是发给自己的,
	 * 那么只需要将skb加入到sock的psock->ingress_msg
	 */
	if (unlikely(skb->sk == sk))
		return sk_psock_skb_ingress_self(psock, skb);

	/* 否则, 就是其他sock发送过来的, 区别就是需要检查接收缓存等 */

	msg = sk_psock_create_ingress_msg(sk, skb);
	if (!msg)
		return -EAGAIN;

	/* This will transition ownership of the data from the socket where
	 * the BPF program was run initiating the redirect to the socket
	 * we will eventually receive this data on. The data will be released
	 * from skb_consume found in __tcp_bpf_recvmsg() after its been copied
	 * into user buffers.
	 */
	skb_set_owner_r(skb, sk);
	err = sk_psock_skb_ingress_enqueue(skb, psock, sk, msg);
	if (err < 0)
		kfree(msg);
	return err;
}

/* Puts an skb on the ingress queue of the socket already assigned to the
 * skb. In this case we do not need to check memory limits or skb_set_owner_r
 * because the skb is already accounted for here.
 */
static int sk_psock_skb_ingress_self(struct sk_psock *psock, struct sk_buff *skb)
{
	struct sk_msg *msg = kzalloc(sizeof(*msg), __GFP_NOWARN | GFP_ATOMIC);
	struct sock *sk = psock->sk;
	int err;

	if (unlikely(!msg))
		return -EAGAIN;
	sk_msg_init(msg);
	skb_set_owner_r(skb, sk);
	err = sk_psock_skb_ingress_enqueue(skb, psock, sk, msg);
	if (err < 0)
		kfree(msg);
	return err;
}

static int sk_psock_handle_skb(struct sk_psock *psock, struct sk_buff *skb,
			       u32 off, u32 len, bool ingress)
{
	if (!ingress) { /* 发送 */
		/* 发送缓存满了则返回EAGAIN稍后再试 */
		if (!sock_writeable(psock->sk))
			return -EAGAIN;
		/* 会调用sendmsg()将skb发送出去 */
		return skb_send_sock(psock->sk, skb, off, len);
	}

	/* 接收数据到psock->ingress_msg, 然后唤醒应用层,
	 * 应用层调用recv()时会调用tcp_bpf_recvmsg()从ingress_msg中接收数据
	 */
	return sk_psock_skb_ingress(psock, skb);
}

static void sk_psock_skb_state(struct sk_psock *psock,
			       struct sk_psock_work_state *state,
			       struct sk_buff *skb,
			       int len, int off)
{
	spin_lock_bh(&psock->ingress_lock);
	if (sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED)) {
		state->skb = skb;
		state->len = len;
		state->off = off;
	} else {
		sock_drop(psock->sk, skb);
	}
	spin_unlock_bh(&psock->ingress_lock);
}

/* 循环处理后备队列psock->ingress_skb, 根据ingress方向(BPF_F_INGRESS标志)接收或发送skb
 * 接收的话则加入到ingress_msg队列, 发送的话则调用sendmsg发送出去
 */
static void sk_psock_backlog(struct work_struct *work)
{
	struct sk_psock *psock = container_of(work, struct sk_psock, work);
	struct sk_psock_work_state *state = &psock->work_state;
	struct sk_buff *skb = NULL;
	bool ingress;
	u32 len, off;
	int ret;

	/* 如果有上次EAGAIN没处理完的继续处理 */
	mutex_lock(&psock->work_mutex);
	if (unlikely(state->skb)) {
		spin_lock_bh(&psock->ingress_lock);
		skb = state->skb;
		len = state->len;
		off = state->off;
		state->skb = NULL;
		spin_unlock_bh(&psock->ingress_lock);
	}
	if (skb)
		goto start;

	/* 循环处理后备队列ingress_skb, 根据ingress方向接收或发送skb */
	while ((skb = skb_dequeue(&psock->ingress_skb))) {
		len = skb->len;
		off = 0;
start:
		ingress = skb_bpf_ingress(skb); /* 获取收发方向, 1为接收, 0为发送 */
		skb_bpf_redirect_clear(skb);
		do {
			ret = -EIO;
			if (!sock_flag(psock->sk, SOCK_DEAD))
				/* 这里负责skb的接收或发送 */
				ret = sk_psock_handle_skb(psock, skb, off,
							  len, ingress);
			if (ret <= 0) {
				if (ret == -EAGAIN) {
					/* 记录到work_state中, 下次进来再处理 */
					sk_psock_skb_state(psock, state, skb,
							   len, off);
					goto end;
				}
				/* Hard errors break pipe and stop xmit. */
				sk_psock_report_error(psock, ret ? -ret : EPIPE);
				sk_psock_clear_state(psock, SK_PSOCK_TX_ENABLED);
				sock_drop(psock->sk, skb);
				goto end;
			}
			off += ret;
			len -= ret;
		} while (len);

		/* 发送的话则需要释放skb */
		if (!ingress)
			kfree_skb(skb);
	}
end:
	mutex_unlock(&psock->work_mutex);
}

struct sk_psock *sk_psock_init(struct sock *sk, int node)
{
	struct sk_psock *psock;
	struct proto *prot;

	write_lock_bh(&sk->sk_callback_lock);

	if (sk->sk_user_data) {
		psock = ERR_PTR(-EBUSY);
		goto out;
	}

	psock = kzalloc_node(sizeof(*psock), GFP_ATOMIC | __GFP_NOWARN, node);
	if (!psock) {
		psock = ERR_PTR(-ENOMEM);
		goto out;
	}

	prot = READ_ONCE(sk->sk_prot);
	psock->sk = sk;
	psock->eval = __SK_NONE;
	psock->sk_proto = prot;
	psock->saved_unhash = prot->unhash;
	psock->saved_close = prot->close;
	psock->saved_write_space = sk->sk_write_space;

	INIT_LIST_HEAD(&psock->link);
	spin_lock_init(&psock->link_lock);

	INIT_WORK(&psock->work, sk_psock_backlog);
	mutex_init(&psock->work_mutex);
	INIT_LIST_HEAD(&psock->ingress_msg);
	spin_lock_init(&psock->ingress_lock);
	skb_queue_head_init(&psock->ingress_skb);

	sk_psock_set_state(psock, SK_PSOCK_TX_ENABLED);
	refcount_set(&psock->refcnt, 1);

 	/* 将psock地址保存在sk->sk_user_data, 后面可以用sk_psock()获取 */
	rcu_assign_sk_user_data_nocopy(sk, psock);
	sock_hold(sk);

out:
	write_unlock_bh(&sk->sk_callback_lock);
	return psock;
}
EXPORT_SYMBOL_GPL(sk_psock_init);

struct sk_psock_link *sk_psock_link_pop(struct sk_psock *psock)
{
	struct sk_psock_link *link;

	spin_lock_bh(&psock->link_lock);
	link = list_first_entry_or_null(&psock->link, struct sk_psock_link,
					list);
	if (link)
		list_del(&link->list);
	spin_unlock_bh(&psock->link_lock);
	return link;
}

static void __sk_psock_purge_ingress_msg(struct sk_psock *psock)
{
	struct sk_msg *msg, *tmp;

	list_for_each_entry_safe(msg, tmp, &psock->ingress_msg, list) {
		list_del(&msg->list);
		sk_msg_free(psock->sk, msg);
		kfree(msg);
	}
}

static void __sk_psock_zap_ingress(struct sk_psock *psock)
{
	struct sk_buff *skb;

	/* 删除ingress_skb队列 */
	while ((skb = skb_dequeue(&psock->ingress_skb)) != NULL) {
		skb_bpf_redirect_clear(skb);
		sock_drop(psock->sk, skb);
	}
	kfree_skb(psock->work_state.skb);
	/* We null the skb here to ensure that calls to sk_psock_backlog
	 * do not pick up the free'd skb.
	 */
	psock->work_state.skb = NULL;
	__sk_psock_purge_ingress_msg(psock); /* 删除ingress_msg队列 */
}

static void sk_psock_link_destroy(struct sk_psock *psock)
{
	struct sk_psock_link *link, *tmp;

	list_for_each_entry_safe(link, tmp, &psock->link, list) {
		list_del(&link->list);
		sk_psock_free_link(link);
	}
}

void sk_psock_stop(struct sk_psock *psock, bool wait)
{
	spin_lock_bh(&psock->ingress_lock);
	sk_psock_clear_state(psock, SK_PSOCK_TX_ENABLED);
	sk_psock_cork_free(psock);
	__sk_psock_zap_ingress(psock); /* 删除ingress_skb和ingress_msg队列 */
	spin_unlock_bh(&psock->ingress_lock);

	if (wait)
		cancel_work_sync(&psock->work);
}

static void sk_psock_done_strp(struct sk_psock *psock);

static void sk_psock_destroy(struct work_struct *work)
{
	struct sk_psock *psock = container_of(to_rcu_work(work),
					      struct sk_psock, rwork);
	/* No sk_callback_lock since already detached. */

	sk_psock_done_strp(psock);

	cancel_work_sync(&psock->work);
	mutex_destroy(&psock->work_mutex);

	psock_progs_drop(&psock->progs);

	sk_psock_link_destroy(psock);
	sk_psock_cork_free(psock);

	if (psock->sk_redir)
		sock_put(psock->sk_redir);
	sock_put(psock->sk);
	kfree(psock);
}

void sk_psock_drop(struct sock *sk, struct sk_psock *psock)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk_psock_restore_proto(sk, psock);
	rcu_assign_sk_user_data(sk, NULL);
	if (psock->progs.stream_parser)
		sk_psock_stop_strp(sk, psock);
	else if (psock->progs.stream_verdict || psock->progs.skb_verdict)
		sk_psock_stop_verdict(sk, psock);
	write_unlock_bh(&sk->sk_callback_lock);

	sk_psock_stop(psock, false);

	INIT_RCU_WORK(&psock->rwork, sk_psock_destroy);
	queue_rcu_work(system_wq, &psock->rwork);
}
EXPORT_SYMBOL_GPL(sk_psock_drop);

/* redir为1说明需要转发到其他sock */
static int sk_psock_map_verd(int verdict, bool redir)
{
	switch (verdict) {
	case SK_PASS: /* PASS表示需要继续, 可能重定向(redir)也可能不修改(!redir) */
		return redir ? __SK_REDIRECT : __SK_PASS;
	case SK_DROP:
	default:
		break;
	}

	return __SK_DROP;
}

int sk_psock_msg_verdict(struct sock *sk, struct sk_psock *psock,
			 struct sk_msg *msg)
{
	struct bpf_prog *prog;
	int ret;

	rcu_read_lock();
	prog = READ_ONCE(psock->progs.msg_parser); /* 获取attach到sockmap上的msg_parser */
	if (unlikely(!prog)) {
		ret = __SK_PASS; /* 无prog程序不修改 */
		goto out;
	}

	sk_msg_compute_data_pointers(msg);
	msg->sk = sk;
	/* 这里执行msg_parser prog程序
	 * 1.如果prog需要重定向到其他sock会调用bpf_msg_redirect_map()/bpf_msg_redirect_hash()
	 * 来重定向到其他sock, 这时会将重定向的sock保存在msg->sk_redir中, BPF_F_INGRESS标志保存在msg->flags
	 * 2.如果prog不需要改变msg的路径, 那么msg->sk_redir为空
	 * 以上两种都是返回SK_PASS, 只有在出错或者需要丢弃时才返回SK_DROP
	 */
	ret = bpf_prog_run_pin_on_cpu(prog, msg);
	/* 将返回值ret转为__sk_action的一种 */
	ret = sk_psock_map_verd(ret, msg->sk_redir);
	psock->apply_bytes = msg->apply_bytes; /* 需要应用同一个结果的字节数 */
	if (ret == __SK_REDIRECT) { /* 需要重定向到其他sock */
		if (psock->sk_redir)
			sock_put(psock->sk_redir);
		psock->sk_redir = msg->sk_redir; /* 重定向目的sock保存到psock */
		if (!psock->sk_redir) { /* 出错 */
			ret = __SK_DROP;
			goto out;
		}
		sock_hold(psock->sk_redir);
	}
out:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(sk_psock_msg_verdict);

static int sk_psock_skb_redirect(struct sk_psock *from, struct sk_buff *skb)
{
	struct sk_psock *psock_other;
	struct sock *sk_other;

	sk_other = skb_bpf_redirect_fetch(skb); /* 获取目的sock */
	/* This error is a buggy BPF program, it returned a redirect
	 * return code, but then didn't set a redirect interface.
	 */
	if (unlikely(!sk_other)) {
		sock_drop(from->sk, skb);
		return -EIO;
	}
	psock_other = sk_psock(sk_other);
	/* This error indicates the socket is being torn down or had another
	 * error that caused the pipe to break. We can't send a packet on
	 * a socket that is in this state so we drop the skb.
	 */
	if (!psock_other || sock_flag(sk_other, SOCK_DEAD)) {
		skb_bpf_redirect_clear(skb);
		sock_drop(from->sk, skb);
		return -EIO;
	}
	spin_lock_bh(&psock_other->ingress_lock);
	if (!sk_psock_test_state(psock_other, SK_PSOCK_TX_ENABLED)) {
		spin_unlock_bh(&psock_other->ingress_lock);
		skb_bpf_redirect_clear(skb);
		sock_drop(from->sk, skb);
		return -EIO;
	}

	/* 将skb加入到目的sock的ingress_skb,
	 * 工作队列sk_psock_backlog会处理接收或发送
	 */
	skb_queue_tail(&psock_other->ingress_skb, skb);
	schedule_work(&psock_other->work);
	spin_unlock_bh(&psock_other->ingress_lock);
	return 0;
}

static void sk_psock_tls_verdict_apply(struct sk_buff *skb,
				       struct sk_psock *from, int verdict)
{
	switch (verdict) {
	case __SK_REDIRECT:
		sk_psock_skb_redirect(from, skb);
		break;
	case __SK_PASS:
	case __SK_DROP:
	default:
		break;
	}
}

int sk_psock_tls_strp_read(struct sk_psock *psock, struct sk_buff *skb)
{
	struct bpf_prog *prog;
	int ret = __SK_PASS;

	rcu_read_lock();
	prog = READ_ONCE(psock->progs.stream_verdict);
	if (likely(prog)) {
		skb->sk = psock->sk;
		skb_dst_drop(skb);
		skb_bpf_redirect_clear(skb);
		ret = bpf_prog_run_pin_on_cpu(prog, skb);
		ret = sk_psock_map_verd(ret, skb_bpf_redirect_fetch(skb));
		skb->sk = NULL;
	}
	sk_psock_tls_verdict_apply(skb, psock, ret);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(sk_psock_tls_strp_read);

static int sk_psock_verdict_apply(struct sk_psock *psock, struct sk_buff *skb,
				  int verdict)
{
	struct sock *sk_other;
	int err = 0;

	switch (verdict) {
	case __SK_PASS: /* 由本sock处理 */
		err = -EIO;
		sk_other = psock->sk;
		if (sock_flag(sk_other, SOCK_DEAD) ||
		    !sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED)) {
			goto out_free;
		}

		skb_bpf_set_ingress(skb); /* 设置接收标志, 后续由自身sock接收 */

		/* If the queue is empty then we can submit directly
		 * into the msg queue. If its not empty we have to
		 * queue work otherwise we may get OOO data. Otherwise,
		 * if sk_psock_skb_ingress errors will be handled by
		 * retrying later from workqueue.
		 */
		/* 如果ingress_skb是空的, 说明没有其他sock重定向过来的数据
		 * 那么就可以直接加入ingress_msg中;
		 * 否则为了确保数据不乱序, 需要加入到ingress_skb中
		 * 再由工作队列sk_psock_backlog统一处理
		 */
		if (skb_queue_empty(&psock->ingress_skb)) {
			/* 将skb转成sk_msg保存到psock->ingress_msg中, 然后唤醒应用层 */
			err = sk_psock_skb_ingress_self(psock, skb);
		}
		if (err < 0) {
			spin_lock_bh(&psock->ingress_lock);
			/* 加到ingress_skb中让工作队列处理 */
			if (sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED)) {
				skb_queue_tail(&psock->ingress_skb, skb);
				schedule_work(&psock->work); /* 工作队列函数sk_psock_backlog */
				err = 0;
			}
			spin_unlock_bh(&psock->ingress_lock);
			if (err < 0) {
				skb_bpf_redirect_clear(skb);
				goto out_free;
			}
		}
		break;
	case __SK_REDIRECT: /* 重定向到其他sock处理 */
		err = sk_psock_skb_redirect(psock, skb);
		break;
	case __SK_DROP:
	default:
out_free:
		sock_drop(psock->sk, skb);
	}

	return err;
}

static void sk_psock_write_space(struct sock *sk)
{
	struct sk_psock *psock;
	void (*write_space)(struct sock *sk) = NULL;

	rcu_read_lock();
	psock = sk_psock(sk);
	if (likely(psock)) {
		if (sk_psock_test_state(psock, SK_PSOCK_TX_ENABLED))
			schedule_work(&psock->work);
		write_space = psock->saved_write_space;
	}
	rcu_read_unlock();
	if (write_space)
		write_space(sk);
}

#if IS_ENABLED(CONFIG_BPF_STREAM_PARSER)
static void sk_psock_strp_read(struct strparser *strp, struct sk_buff *skb)
{
	struct sk_psock *psock;
	struct bpf_prog *prog;
	int ret = __SK_DROP;
	struct sock *sk;

	rcu_read_lock();
	sk = strp->sk;
	psock = sk_psock(sk);
	if (unlikely(!psock)) {
		sock_drop(sk, skb);
		goto out;
	}
	prog = READ_ONCE(psock->progs.stream_verdict);
	if (likely(prog)) {
		skb->sk = sk;
		skb_dst_drop(skb);
		skb_bpf_redirect_clear(skb);
 		/* 执行我们attach到sockmap的stream_verdict bpf程序 */
		ret = bpf_prog_run_pin_on_cpu(prog, skb);
		/* 将返回值ret转为__sk_action的一种 */
		ret = sk_psock_map_verd(ret, skb_bpf_redirect_fetch(skb));
		skb->sk = NULL;
	}
	/* 真正处理数据接收或重定向 */
	sk_psock_verdict_apply(psock, skb, ret);
out:
	rcu_read_unlock();
}

static int sk_psock_strp_read_done(struct strparser *strp, int err)
{
	return err;
}

static int sk_psock_strp_parse(struct strparser *strp, struct sk_buff *skb)
{
	struct sk_psock *psock = container_of(strp, struct sk_psock, strp);
	struct bpf_prog *prog;
	int ret = skb->len;

	rcu_read_lock();
	prog = READ_ONCE(psock->progs.stream_parser);
	if (likely(prog)) {
		skb->sk = psock->sk;
 		/* 执行我们attach到sockmap的stream_parser bpf程序 */
		ret = bpf_prog_run_pin_on_cpu(prog, skb);
		skb->sk = NULL;
	}
	rcu_read_unlock();
	return ret;
}

/* Called with socket lock held. */
static void sk_psock_strp_data_ready(struct sock *sk)
{
	struct sk_psock *psock;

	rcu_read_lock();
	psock = sk_psock(sk);
	if (likely(psock)) {
		if (tls_sw_has_ctx_rx(sk)) {
			psock->saved_data_ready(sk);
		} else {
			write_lock_bh(&sk->sk_callback_lock);
			strp_data_ready(&psock->strp); /* 调用strparser接收 */
			write_unlock_bh(&sk->sk_callback_lock);
		}
	}
	rcu_read_unlock();
}

int sk_psock_init_strp(struct sock *sk, struct sk_psock *psock)
{
	static const struct strp_callbacks cb = {
		.rcv_msg	= sk_psock_strp_read,
		.read_sock_done	= sk_psock_strp_read_done,
		.parse_msg	= sk_psock_strp_parse,
	};

	/* 初始化strparser, 设置上面cb的回调函数 */
	return strp_init(&psock->strp, sk, &cb);
}

void sk_psock_start_strp(struct sock *sk, struct sk_psock *psock)
{
	if (psock->saved_data_ready)
		return;

	psock->saved_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = sk_psock_strp_data_ready;
	sk->sk_write_space = sk_psock_write_space;
}

void sk_psock_stop_strp(struct sock *sk, struct sk_psock *psock)
{
	if (!psock->saved_data_ready)
		return;

	sk->sk_data_ready = psock->saved_data_ready;
	psock->saved_data_ready = NULL;
	strp_stop(&psock->strp);
}

static void sk_psock_done_strp(struct sk_psock *psock)
{
	/* Parser has been stopped */
	if (psock->progs.stream_parser)
		strp_done(&psock->strp);
}
#else
static void sk_psock_done_strp(struct sk_psock *psock)
{
}
#endif /* CONFIG_BPF_STREAM_PARSER */

static int sk_psock_verdict_recv(read_descriptor_t *desc, struct sk_buff *skb,
				 unsigned int offset, size_t orig_len)
{
	struct sock *sk = (struct sock *)desc->arg.data;
	struct sk_psock *psock;
	struct bpf_prog *prog;
	int ret = __SK_DROP;
	int len = skb->len;

	/* clone here so sk_eat_skb() in tcp_read_sock does not drop our data */
	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb) {
		desc->error = -ENOMEM;
		return 0;
	}

	rcu_read_lock();
	psock = sk_psock(sk);
	if (unlikely(!psock)) {
		len = 0;
		sock_drop(sk, skb);
		goto out;
	}
	/* 获取stream_verdict或skb_verdict prog程序 */
	prog = READ_ONCE(psock->progs.stream_verdict);
	if (!prog)
		prog = READ_ONCE(psock->progs.skb_verdict);
	if (likely(prog)) {
		skb->sk = sk;
		skb_dst_drop(skb);
		skb_bpf_redirect_clear(skb);
 		/* 执行我们attach到sockmap的stream_verdict/skb_verdict bpf程序 */
		ret = bpf_prog_run_pin_on_cpu(prog, skb);
		/* 将返回值ret转为__sk_action的一种 */
		ret = sk_psock_map_verd(ret, skb_bpf_redirect_fetch(skb));
		skb->sk = NULL;
	}
	/* 真正处理数据接收或重定向 */
	if (sk_psock_verdict_apply(psock, skb, ret) < 0)
		len = 0;
out:
	rcu_read_unlock();
	return len;
}

static void sk_psock_verdict_data_ready(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	read_descriptor_t desc;

	if (unlikely(!sock || !sock->ops || !sock->ops->read_sock))
		return;

	desc.arg.data = sk;
	desc.error = 0;
	desc.count = 1;

	/* tcp调用tcp_read_sock()
	 * 主要就是读取sk_receive_queue中skb, 然后调用sk_psock_verdict_recv()处理
	 */
	sock->ops->read_sock(sk, &desc, sk_psock_verdict_recv);
}

void sk_psock_start_verdict(struct sock *sk, struct sk_psock *psock)
{
	if (psock->saved_data_ready)
		return;

	psock->saved_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = sk_psock_verdict_data_ready; /* 替换为verdict的核心接收处理函数 */
	sk->sk_write_space = sk_psock_write_space;
}

void sk_psock_stop_verdict(struct sock *sk, struct sk_psock *psock)
{
	if (!psock->saved_data_ready)
		return;

	sk->sk_data_ready = psock->saved_data_ready;
	psock->saved_data_ready = NULL;
}
