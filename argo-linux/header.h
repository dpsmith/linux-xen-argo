
static void argo_free_ring (struct ring *r);

static int argo_release_ring(struct ring *r);

static int
argo_set_ring_size(struct argo_private *p, uint32_t ring_size)

void argo_ring_reset(struct argo_ring_id *ring, uint32_t conid, xen_argo_addr_t *dst)

ssize_t
argo_sendto(struct argo_private * p, const void *buf, size_t len, int flags,
            xen_argo_addr_t * addr, int nonblock)

ssize_t
argo_recvfrom(struct argo_private * p, void *buf, size_t len, int flags,
              xen_argo_addr_t * addr, int nonblock)

static int
argo_listen(struct argo_private *p)

static int
argo_bind(struct argo_private *p, struct argo_ring_id *ring_id)

static int
argo_accept(struct argo_private *p, struct xen_argo_addr *peer, int nonblock)

static int
argo_connect(struct argo_private *p, xen_argo_addr_t *peer, int nonblock)

static int
argo_get_sock_name (struct argo_private *p, struct argo_ring_id *id)

static int
argo_get_sock_type(struct argo_private *p, int *type)

static int
argo_get_peer_name (struct argo_private *p, xen_argo_addr_t * id)
