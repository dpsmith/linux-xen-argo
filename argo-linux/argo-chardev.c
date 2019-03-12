
static int chardev_open_dgram(struct inode *inode, struct file *f)
{
	struct argo_private *p;

	p = kmalloc(sizeof(struct argo_private), GFP_KERNEL);
	if ( !p )
		return -ENOMEM;

	memset(p, 0, sizeof(struct argo_private));
	p->state = ARGO_STATE_IDLE;
	p->desired_ring_size = DEFAULT_RING_SIZE;
	p->r = NULL;
	p->ptype = ARGO_PTYPE_DGRAM;
	p->send_blocked = 0;

	init_waitqueue_head(&p->readq);
	init_waitqueue_head(&p->writeq);

	//TODO: replace with kernel spinlock
	argo_spin_lock_init(&p->pending_recv_lock);
	INIT_LIST_HEAD(&p->pending_recv_list);
	atomic_set(&p->pending_recv_count, 0);

	printk(KERN_DEBUG "argo_open priv %p\n", p);

	f->private_data = p;
	f->f_flags = O_RDWR;

	return 0;
}

static int chardev_open_stream(struct inode *inode, struct file *f)
{
	struct argo_private *p;

	p = kmalloc(sizeof(struct argo_private), GFP_KERNEL);
	if ( !p )
		return -ENOMEM;

	memset(p, 0, sizeof(struct argo_private));
	p->state = ARGO_STATE_IDLE;
	p->desired_ring_size = DEFAULT_RING_SIZE;
	p->r = NULL;
	p->ptype = ARGO_PTYPE_STREAM;
	p->send_blocked = 0;

	init_waitqueue_head(&p->readq);
	init_waitqueue_head(&p->writeq);

	//TODO: replace with kernel spinlock
	argo_spin_lock_init(&p->pending_recv_lock);
	INIT_LIST_HEAD(&p->pending_recv_list);
	atomic_set(&p->pending_recv_count, 0);

	printk(KERN_DEBUG "argo_open priv %p\n", p);

	f->private_data = p;
	f->f_flags = O_RDWR;

	return 0;
}

static int chardev_release(struct inode *inode, struct file *f)
{
	struct argo_private *p = (struct argo_private *) f->private_data;
	struct ring *r = p->r;
	unsigned long flags;
	struct pending_recv *pending, *t;
	static volatile char tmp;
	int need_ring_free = 0;

	
	/* XC-8841 - make sure the ring info is properly mapped so we won't efault in xen
	* passing pointers to hypercalls.
	* Read the first and last byte, that should repage the structure */
	if (r && r->ring )
		tmp = *((char*)r->ring) + *(((char*)r->ring)
			+ sizeof(xen_argo_ring_t)-1);

	if ( p->ptype == ARGO_PTYPE_STREAM ) {
		switch ( p->state ) {
		/* EC: Assuming our process is killed while SYN is waiting in the ring 
		*     to be consumed (accept is yet to be scheduled).
		*     Connect will never wake up while the ring is destroy thereafter.
		*     We reply RST to every pending SYN in that situation.
		*     Still, the timeout handling on connect is required.
		*     If the connecting domain is scheduled by Xen while
		*     we're walking that list, it could possibly send another SYN by
		*     the time we're done (very unlikely though).
		*     This loop just speeds up the things in most cases.
		*/
		case ARGO_STATE_LISTENING:
			//TODO: replace with kernel spinlock
			argo_spin_lock(&r->sponsor->pending_recv_lock);

			list_for_each_entry_safe(pending, t,
					&r->sponsor->pending_recv_list, node) {
				if ( pending->sh.flags & ARGO_SHF_SYN ) {
					/* Consume the SYN */
					list_del(&pending->node);
					atomic_dec(&r->sponsor->pending_recv_count);

					xmit_queue_rst_to(&r->id,
							  pending->sh.conid,
							  &pending->from);
					kfree(pending);
				}
			}
			//TODO: replace with kernel spinlock
			argo_spin_unlock(&r->sponsor->pending_recv_lock);
			break;
		case ARGO_STATE_CONNECTED:
		case ARGO_STATE_CONNECTING:
		case ARGO_STATE_ACCEPTED:
			DEBUG_APPLE;
			xmit_queue_rst_to(&r->id, p->conid, &p->peer);
			break;
		default:
			break;
		}
	}

	argo_write_lock_irqsave(&list_lock, flags);

	DEBUG_APPLE;
	if ( !p->r ) {
		argo_write_unlock_irqrestore(&list_lock, flags);
		DEBUG_APPLE;
		break;
	}
	DEBUG_APPLE;

	if ( p != r->sponsor ) {
		DEBUG_APPLE;

		need_ring_free = argo_release_ring(r);
		list_del(&p->node);
		argo_write_unlock_irqrestore(&list_lock, flags);

		DEBUG_APPLE;
		break;
	}
	DEBUG_APPLE;

	//Send RST

	DEBUG_APPLE;
	r->sponsor = NULL;
	need_ring_free = argo_release_ring(r);
	argo_write_unlock_irqrestore(&list_lock, flags);

	while (!list_empty(&p->pending_recv_list)) {
		pending = list_first_entry(&p->pending_recv_list, struct pending_recv, node);

		list_del(&pending->node);
		kfree(pending);
		atomic_dec(&p->pending_recv_count);
	}

	if ( need_ring_free )
		argo_free_ring(r);

	kfree(p);

	return 0;
}

static ssize_t chardev_write(struct file *f, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct argo_private *p = f->private_data;
	int nonblock = f->f_flags & O_NONBLOCK;

	return argo_sendto(p, buf, count, 0, NULL, nonblock);
}

static ssize_t chardev_read(struct file *f, char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct argo_private *p = f->private_data;
	int nonblock = f->f_flags & O_NONBLOCK;

	return argo_recvfrom(p, (void *) buf, count, 0, NULL, nonblock);
}

static long chardev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret;
	int nonblock = f->f_flags & O_NONBLOCK;
	struct argo_private *p = f->private_data;

	printk(KERN_DEBUG "argo_ioctl cmd=%x pid=%d\n", cmd, current->pid);

	if (_IOC_TYPE(cmd) != ARGO_TYPE)
		return -ENOTTY;

	switch (cmd) {
	case ARGOIOCSETRINGSIZE:
		uint32_t ring_size;

		if (get_user(ring_size, (uint32_t __user *)arg)) {
			ret = -EFAULT;
			break;
		}

		ret = argo_set_ring_size(p, ring_size);
		break;
	case ARGOIOCBIND:
		struct argo_ring_id ring_id;

		if (copy_from_user(&ring_id, (void __user *)arg,
				   sizeof(struct argo_ring_id)) ) {
			ret = -EFAULT;
			break;
		}

		ret = argo_bind(p, &ring_id);
		break;
	case ARGOIOCGETSOCKNAME:
		struct argo_ring_id ring_id;

		if (!access_ok(VERIFY_WRITE, arg, sizeof(struct argo_ring_id))) {
			ret = -EFAULT;
			break;
		}

		argo_get_sock_name(p, &ring_id);

		if (copy_to_user((void __user *)arg, &ring_id,
				 sizeof(struct argo_ring_id)) ) {
			ret = -EFAULT;
			break;
		}

		ret = 0;
		break;
	case ARGOIOCGETSOCKTYPE:
		int sock_type;

		if (!access_ok(VERIFY_WRITE, arg, sizeof(int))) {
			ret = -EFAULT;
			break;
		}

		argo_get_sock_type(p, &sock_type);
		if (put_user(sock_type, (int __user *)arg))
			ret = -EFAULT;
		else
			ret = 0;

		break;
	case ARGOIOCGETPEERNAME:
		xen_argo_addr_t addr;

		if (!access_ok(VERIFY_WRITE, arg, sizeof(xen_argo_addr_t))) {
			ret = -EFAULT;
			break;
		}

		ret = argo_get_peer_name(p, &addr);
		if (ret)
			break;

		if (copy_to_user((void __user *)arg, &addr,
				 sizeof(xen_argo_addr_t)))
			ret = -EFAULT;
		else
			ret = 0;

		break;
	case ARGOIOCCONNECT:
		xen_argo_addr_t connect_addr;

		if (arg) {
			if (copy_from_user(&connect_addr, (void __user *)arg,
			    		   sizeof(xen_argo_addr_t)) ) {
				ret = -EFAULT;
				break;
			}
		}

		//For for the lazy do a bind if it wasn't done
		if (p->state == ARGO_STATE_IDLE) {
			struct argo_ring_id id;

			memset(&id, 0, sizeof(id));
			id.partner_id = XEN_ARGO_DOMID_ANY;
			id.domain_id = XEN_ARGO_DOMID_ANY;
			id.aport = 0;
			ret = argo_bind(p, &id);
			if (ret)
				break;
		}

		if (arg)
			ret = argo_connect(p, &connect_addr, nonblock);
		else
			ret = argo_connect(p, NULL, nonblock);

		break;
	case ARGOIOCGETCONNECTERR:
		unsigned long flags;

		if (!access_ok(VERIFY_WRITE, arg, sizeof(int))) {
			ret = -EFAULT;
			break;
		}

		argo_spin_lock_irqsave(&p->pending_recv_lock, flags);

		if (put_user(p->pending_error, (int __user *)arg)) {
			ret = -EFAULT;
		} else {
			p->pending_error = 0;
			ret = 0;
		}

		argo_spin_unlock_irqrestore(&p->pending_recv_lock, flags);

		break;
	case ARGOIOCLISTEN:
		ret = argo_listen(p);
		break;
	case ARGOIOCACCEPT
		xen_argo_addr_t addr;

		if (!access_ok(VERIFY_WRITE, arg, sizeof(xen_argo_addr_t))) {
			ret = -EFAULT;
			break;
		}

		ret = argo_accept(p, &addr, nonblock);
		if (ret < 0)
			break;

		if (copy_to_user((void __user *)arg, &addr,
				 sizeof(xen_argo_addr_t)))
			ret = -EFAULT;
		else
			ret = 0;

		break;
	case ARGOIOCSEND:
		struct argo_dev a;
		xen_argo_addr_t addr;

		if (copy_from_user(&a, (void __user *)arg,
				   sizeof(struct argo_dev))) {
			ret = -EFAULT;
			break;
		}

		if (a.addr) {
			if (copy_from_user(&addr, (void __user *)a.addr,
					   sizeof(xen_argo_addr_t)) ) {
				ret = -EFAULT;
				break;
			}

			ret = argo_sendto(p, a.buf, a.len, a.flags,
					 &addr, nonblock);
		} else {
			ret = argo_sendto(p, a.buf, a.len, a.flags,
					 NULL, nonblock);
		}

		break;
	case ARGOIOCRECV:
		struct argo_dev a;
		xen_argo_addr_t addr;

		if (copy_from_user(&a, (void __user *)arg,
		    sizeof(struct argo_dev))) {
			ret = -EFAULT;
			break;
		}

		if (a.addr) {
			if (copy_from_user(&addr, a.addr,
					   sizeof(xen_argo_addr_t))) {
				ret = -EFAULT;
				break;
			}

			ret = argo_recvfrom(p, a.buf, a.len, a.flags,
					   &addr, nonblock);
			if (ret < 0)
				break;

			if (copy_to_user(a.addr, &addr, sizeof(xen_argo_addr_t)))
				ret = -EFAULT;
			else
				ret = 0;
		} else {
			ret = argo_recvfrom(p, a.buf, a.len, a.flags,
					   NULL, nonblock);
		}

		break;
	default:
		printk(KERN_ERR "unknown ioctl: cmd=%x ARGOIOCACCEPT=%lx\n",
			cmd, ARGOIOCACCEPT);
		ret = -ENOTTY;
	}

	printk (KERN_DEBUG "argo_ioctl cmd=%x pid=%d result=%d\n",
		cmd, current->pid, rc);
	return ret;
}

#ifdef CONFIG_COMPAT
static long chardev_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int ret;
	int nonblock = f->f_flags & O_NONBLOCK;
	struct argo_private *p = f->private_data;

	switch (cmd) {
	case ARGOIOCSEND32:
		struct argo_dev a;
		struct argo_dev_32 a32;
		xen_argo_addr_t addr, *paddr = NULL;

		if (copy_from_user(&a32, (void __user *)arg, sizeof(a32))) {
			ret = -EFAULT;
			break;
		}

		a.buf = compat_ptr(a32.buf);
		a.len = a32.len;
		a.flags = a32.flags;
		a.addr = compat_ptr(a32.addr);

		if (a.addr) {
			if (copy_from_user(&addr, (void __user *)a.addr,
					   sizeof(xen_argo_addr_t))) {
				ret = -EFAULT;
				break;
			}
			paddr = &addr;
		}

		ret = argo_sendto(p, a.buf, a.len, a.flags, paddr, nonblock);
		break;
	case ARGOIOCRECV32:
		struct argo_dev_32 a32;
		struct argo_dev a;
		xen_argo_addr_t addr;

		if (copy_from_user(&a32, (void __user *)arg, sizeof(a32))) {
			ret = -EFAULT;
			break;
		}

		a.buf = compat_ptr(a32.buf);
		a.len = a32.len;
		a.flags = a32.flags;
		a.addr = compat_ptr(a32.addr);

		if (a.addr) {
			if (copy_from_user(&addr, a.addr,
					   sizeof(xen_argo_addr_t))) {
				ret = -EFAULT;
				break;
			}

			ret = argo_recvfrom(p, a.buf, a.len, a.flags,
					   &addr, nonblock);
			if (ret < 0)
				break;

			if (copy_to_user(a.addr, &addr, sizeof(xen_argo_addr_t)))
				ret = -EFAULT;
			else
				ret = 0;
		} else {
			ret = argo_recvfrom(p, a.buf, a.len, a.flags,
					   NULL, nonblock);
		}

		break;
	default:
		ret = argo_ioctl(f, cmd, (unsigned long)compat_ptr(arg));
	}

	return ret;
}
#endif

static unsigned int chardev_poll(struct file *f, poll_table * pt)
{
	//FIXME
	unsigned int mask = 0;
	struct argo_private *p = f->private_data;
	argo_read_lock(&list_lock);

	switch (p->ptype) {
        case ARGO_PTYPE_DGRAM:
            switch (p->state) {
                case ARGO_STATE_CONNECTED:
                    //FIXME: maybe do something smart here
                case ARGO_STATE_BOUND:
                    poll_wait(f, &p->readq, pt);
                    mask |= POLLOUT | POLLWRNORM;
                    if ( p->r->ring->tx_ptr != p->r->ring->rx_ptr )
                        mask |= POLLIN | POLLRDNORM;
                    break;
                default:
                    break;
            }
            break;

	case ARGO_PTYPE_STREAM:
		switch (p->state) {
		case ARGO_STATE_BOUND:
			break;
		case ARGO_STATE_LISTENING:
			poll_wait(f, &p->readq, pt);
			if (!list_empty(&p->pending_recv_list))
				mask |= POLLIN | POLLRDNORM;
			break;
		case ARGO_STATE_ACCEPTED:
		case ARGO_STATE_CONNECTED:
			poll_wait(f, &p->readq, pt);
			poll_wait(f, &p->writeq, pt);
			if (!p->send_blocked)
				mask |= POLLOUT | POLLWRNORM;
			if (!list_empty(&p->pending_recv_list))
				mask |= POLLIN | POLLRDNORM;
			break;
		case ARGO_STATE_CONNECTING:
			poll_wait(f, &p->writeq, pt);
			break;
		case ARGO_STATE_DISCONNECTED:
			mask |= POLLOUT | POLLWRNORM;
			mask |= POLLIN | POLLRDNORM;
			break;
		case ARGO_STATE_IDLE:
			break;
		}
		break;
	}

	argo_read_unlock(&list_lock);
	return mask;
}

static const struct file_operations chardev_fops_stream = {
	.owner = THIS_MODULE,
	.write = chardev_write,
	.read = chardev_read,
	.unlocked_ioctl = chardev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = chardev_compat_ioctl,
#endif
	.open = chardev_open_stream,
	.release = chardev_release,
	.poll = chardev_poll,
};

static const struct file_operations chardev_fops_dgram = {
	.owner = THIS_MODULE,
	.write = chardev_write,
	.read = chardev_read,
	.unlocked_ioctl = chardev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = chardev_compat_ioctl,
#endif
	.open = chardev_open_dgram,
	.release = chardev_release,
	.poll = chardev_poll,
};


static struct miscdevice chardev_miscdev_dgram = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "argo_dgram",
	.fops = &chardev_fops_dgram,
};

static struct miscdevice chardev_miscdev_stream = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "argo_stream",
	.fops = &chardev_fops_stream,
};

static int __init argo_chardev_init()
{
	int err;

#ifdef XC_DKMS
	if ( !xen_hvm_domain() )
		return -ENODEV;
#else
#ifdef is_running_on_xen
	if ( !is_running_on_xen() )
		return -ENODEV;
#else
	if ( !xen_domain() )
		return -ENODEV;
#endif
#endif
	err = misc_register(&chardev_miscdev_dgram);
	if (err) {
		printk(KERN_ERR "Could not register /dev/argo_dgram\n");
		return err;
	}

	err = misc_register (&chardev_miscdev_stream);
	if (err) {
		printk(KERN_ERR "Could not register /dev/argo_stream\n");
		return err;
	}

}

static void __exit argo_chardev_cleanup(void)
{
    misc_deregister(&chardev_miscdev_dgram);
    misc_deregister(&chardev_miscdev_stream);
}

module_init(argo_chardev_init);
module_exit(argo_chardev_cleanup);
MODULE_LICENSE("GPL");
