// SPDX-License-Identifier: GPL-2.0-only
/*
 * net/sched/sch_mq.c		Classful multiqueue dummy scheduler
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>

struct mq_sched {
	struct Qdisc		**qdiscs;
};

static int mq_offload(struct Qdisc *sch, enum tc_mq_command cmd)
{
	struct net_device *dev = qdisc_dev(sch);
	struct tc_mq_qopt_offload opt = {
		.command = cmd,
		.handle = sch->handle,
	};

	if (!tc_can_offload(dev) || !dev->netdev_ops->ndo_setup_tc)
		return -EOPNOTSUPP;

	return dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_QDISC_MQ, &opt);
}

static int mq_offload_stats(struct Qdisc *sch)
{
	struct tc_mq_qopt_offload opt = {
		.command = TC_MQ_STATS,
		.handle = sch->handle,
		.stats = {
			.bstats = &sch->bstats,
			.qstats = &sch->qstats,
		},
	};

	return qdisc_offload_dump_helper(sch, TC_SETUP_QDISC_MQ, &opt);
}

static void mq_destroy(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	unsigned int ntx;

	mq_offload(sch, TC_MQ_DESTROY);

	if (!priv->qdiscs)
		return;
	for (ntx = 0; ntx < dev->num_tx_queues && priv->qdiscs[ntx]; ntx++)
		qdisc_put(priv->qdiscs[ntx]);
	kfree(priv->qdiscs);
}

static int mq_init(struct Qdisc *sch, struct nlattr *opt,
		   struct netlink_ext_ack *extack)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct netdev_queue *dev_queue;
	struct Qdisc *qdisc;
	unsigned int ntx;

	/* mq只能设置在ROOT上 */
	if (sch->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	/* mq只有网卡多队列才能用 */
	if (!netif_is_multiqueue(dev))
		return -EOPNOTSUPP;

	/* pre-allocate qdiscs, attachment can't fail */
	/* 分配网卡队列个数的qdisc, 用于保存网卡队列自己的qdisc */
	priv->qdiscs = kcalloc(dev->num_tx_queues, sizeof(priv->qdiscs[0]),
			       GFP_KERNEL);
	if (!priv->qdiscs)
		return -ENOMEM;

	/* 循环针对每个网卡队列设置将default_qdisc保存在priv->qdiscs数组中,
	 * (mq_attach()时才真正设置到网卡队列中)
	 */
	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		dev_queue = netdev_get_tx_queue(dev, ntx);
		/*设置为default_qdisc(即/proc/sys/net/core/default_qdisc)
		 * parent为mq的handle:ntx+1(对应tc要设置时指定的parent)
		 */
		qdisc = qdisc_create_dflt(dev_queue, get_default_qdisc_ops(dev, ntx),
					  TC_H_MAKE(TC_H_MAJ(sch->handle),
						    TC_H_MIN(ntx + 1)),
					  extack);
		if (!qdisc)
			return -ENOMEM;
		priv->qdiscs[ntx] = qdisc; /* qdisc保存在priv中 */
		qdisc->flags |= TCQ_F_ONETXQUEUE | TCQ_F_NOPARENT;
	}

	sch->flags |= TCQ_F_MQROOT;

	mq_offload(sch, TC_MQ_CREATE);
	return 0;
}

static void mq_attach(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct Qdisc *qdisc, *old;
	unsigned int ntx;

	/* 循环网络队列设置qdisc */
	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		qdisc = priv->qdiscs[ntx]; /* 在mq_init()中将qdisc保存在priv中 */
		old = dev_graft_qdisc(qdisc->dev_queue, qdisc); /* 设置新的并返回旧的 */
		if (old)
			qdisc_put(old);
#ifdef CONFIG_NET_SCHED
		if (ntx < dev->real_num_tx_queues)
			qdisc_hash_add(qdisc, false);
#endif

	}
	kfree(priv->qdiscs);
	priv->qdiscs = NULL;
}

static int mq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct net_device *dev = qdisc_dev(sch);
	struct Qdisc *qdisc;
	unsigned int ntx;

	sch->q.qlen = 0;
	gnet_stats_basic_sync_init(&sch->bstats);
	memset(&sch->qstats, 0, sizeof(sch->qstats));

	/* MQ supports lockless qdiscs. However, statistics accounting needs
	 * to account for all, none, or a mix of locked and unlocked child
	 * qdiscs. Percpu stats are added to counters in-band and locking
	 * qdisc totals are added at end.
	 */
	/* mq的统计是遍历所有网卡队列的qdisc相加 */
	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		qdisc = rtnl_dereference(netdev_get_tx_queue(dev, ntx)->qdisc_sleeping);
		spin_lock_bh(qdisc_lock(qdisc));

		gnet_stats_add_basic(&sch->bstats, qdisc->cpu_bstats,
				     &qdisc->bstats, false);
		gnet_stats_add_queue(&sch->qstats, qdisc->cpu_qstats,
				     &qdisc->qstats);
		sch->q.qlen += qdisc_qlen(qdisc);

		spin_unlock_bh(qdisc_lock(qdisc));
	}

	return mq_offload_stats(sch);
}

static struct netdev_queue *mq_queue_get(struct Qdisc *sch, unsigned long cl)
{
	struct net_device *dev = qdisc_dev(sch);
	unsigned long ntx = cl - 1;

	if (ntx >= dev->num_tx_queues)
		return NULL;
	return netdev_get_tx_queue(dev, ntx);
}

static struct netdev_queue *mq_select_queue(struct Qdisc *sch,
					    struct tcmsg *tcm)
{
	return mq_queue_get(sch, TC_H_MIN(tcm->tcm_parent));
}

static int mq_graft(struct Qdisc *sch, unsigned long cl, struct Qdisc *new,
		    struct Qdisc **old, struct netlink_ext_ack *extack)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, cl);
	struct tc_mq_qopt_offload graft_offload;
	struct net_device *dev = qdisc_dev(sch);

	if (dev->flags & IFF_UP)
		dev_deactivate(dev);

	*old = dev_graft_qdisc(dev_queue, new);
	if (new)
		new->flags |= TCQ_F_ONETXQUEUE | TCQ_F_NOPARENT;
	if (dev->flags & IFF_UP)
		dev_activate(dev);

	graft_offload.handle = sch->handle;
	graft_offload.graft_params.queue = cl - 1;
	graft_offload.graft_params.child_handle = new ? new->handle : 0;
	graft_offload.command = TC_MQ_GRAFT;

	qdisc_offload_graft_helper(qdisc_dev(sch), sch, new, *old,
				   TC_SETUP_QDISC_MQ, &graft_offload, extack);
	return 0;
}

static struct Qdisc *mq_leaf(struct Qdisc *sch, unsigned long cl)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, cl);

	return rtnl_dereference(dev_queue->qdisc_sleeping);
}

static unsigned long mq_find(struct Qdisc *sch, u32 classid)
{
	unsigned int ntx = TC_H_MIN(classid);

	if (!mq_queue_get(sch, ntx))
		return 0;
	return ntx;
}

static int mq_dump_class(struct Qdisc *sch, unsigned long cl,
			 struct sk_buff *skb, struct tcmsg *tcm)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, cl);

	tcm->tcm_parent = TC_H_ROOT;
	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = rtnl_dereference(dev_queue->qdisc_sleeping)->handle;
	return 0;
}

static int mq_dump_class_stats(struct Qdisc *sch, unsigned long cl,
			       struct gnet_dump *d)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, cl);

	sch = rtnl_dereference(dev_queue->qdisc_sleeping);
	if (gnet_stats_copy_basic(d, sch->cpu_bstats, &sch->bstats, true) < 0 ||
	    qdisc_qstats_copy(d, sch) < 0)
		return -1;
	return 0;
}

static void mq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct net_device *dev = qdisc_dev(sch);
	unsigned int ntx;

	if (arg->stop)
		return;

	arg->count = arg->skip;
	for (ntx = arg->skip; ntx < dev->num_tx_queues; ntx++) {
		if (!tc_qdisc_stats_dump(sch, ntx + 1, arg))
			break;
	}
}

static const struct Qdisc_class_ops mq_class_ops = {
	.select_queue	= mq_select_queue,
	.graft		= mq_graft,
	.leaf		= mq_leaf,
	.find		= mq_find,
	.walk		= mq_walk,
	.dump		= mq_dump_class,
	.dump_stats	= mq_dump_class_stats,
};

/* mq不需要enqueue和dequeue, 因为mq只是一个框架来管理各个网卡队列的qdisc,
 * 网卡队列中的qdisc还是用的其他的(比如pfifo/fq_codel),
 * 而dev_queue_xmit发送时也是直接取网卡队列的qdisc, 不会调用mq
 */
struct Qdisc_ops mq_qdisc_ops __read_mostly = {
	.cl_ops		= &mq_class_ops,
	.id		= "mq",
	.priv_size	= sizeof(struct mq_sched),
	.init		= mq_init,	/* 分配并保存网卡队列的qdisc */
	.destroy	= mq_destroy,
	.attach		= mq_attach,	/* 将qdisc设置到网卡队列 */
	.change_real_num_tx = mq_change_real_num_tx,
	.dump		= mq_dump,
	.owner		= THIS_MODULE,
};
