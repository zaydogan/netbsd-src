/*	$NetBSD: nfs.c,v 1.48 2014/03/20 03:13:18 christos Exp $	*/

/*-
 *  Copyright (c) 1993 John Brezak
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * XXX Does not currently implement:
 * XXX
 * XXX LIBSA_NO_FS_CLOSE
 * XXX LIBSA_NO_FS_SEEK
 * XXX LIBSA_NO_FS_WRITE
 * XXX LIBSA_NO_FS_SYMLINK (does this even make sense?)
 * XXX LIBSA_FS_SINGLECOMPONENT (does this even make sense?)
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#ifdef _STANDALONE
#include <lib/libkern/libkern.h>
#else
#include <string.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>

#include "rpcv2.h"
#include "nfsv2.h"

#include "stand.h"
#include "net.h"
#include "nfs.h"
#include "rpc.h"

#if !defined(NFS_V3_ONLY) && !defined(NFS_V2_V3)
#define NFS_V2_ONLY
#endif

#define NFSREAD_MIN_SIZE	1024
#define NFSREAD_MAX_SIZE	16384

/* NFS v3 definitions */
#define NFS_V3MAXFHSIZE		64
#define NFS_VER3		3
#define RPCMNT_VER3		3
#define NFSPROCV3_LOOKUP	3
#define NFSPROCV3_READLINK	5
#define NFSPROCV3_READ		6

typedef struct {
	uint32_t val[2];
} n_quad;

struct nfsv3_time {
	uint32_t nfs_sec;
	uint32_t nfs_nsec;
};

struct nfsv3_fattrs {
	uint32_t fa_type;
	uint32_t fa_mode;
	uint32_t fa_nlink;
	uint32_t fa_uid;
	uint32_t fa_gid;
	n_quad fa_size;
	n_quad fa_used;
	n_quad fa_rdev;
	n_quad fa_fsid;
	n_quad fa_fileid;
	struct nfsv3_time fa_atime;
	struct nfsv3_time fa_mtime;
	struct nfsv3_time fa_ctime;
};

struct nfs_iodesc {
	struct iodesc *iodesc;
	off_t off;
	uint32_t fhsize;
	u_char fh[NFS_V3MAXFHSIZE];
	union {
		struct nfsv2_fattrs v2;
		struct nfsv3_fattrs v3;
	} fa;	/* all in network order */
	uint64_t cookie;
};

struct nfs_iodesc nfs_root_node;

/* NFNON=0, NFREG=1, NFDIR=2, NFBLK=3, NFCHR=4, NFLNK=5, NFSOCK=6, NFFIFO=7 */
static const int nfs_stat_types[9] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK, S_IFSOCK, S_IFIFO, 0
};

#ifndef NFS_V3_ONLY
/*
 * NFS v2
 */
FS_DEF(nfsv2);
int nfsv2_mount(int, struct in_addr, char *);

/*
 * Fetch the root file handle (call mount daemon)
 * On error, return non-zero and set errno.
 */
static int
nfsv2_getrootfh(struct iodesc *d, char *path, u_char *fhp)
{
	int len;
	struct args {
		n_long	len;
		char	path[FNAME_SIZE];
	} *args;
	struct repl {
		n_long	errno;
		u_char	fh[NFS_FHSIZE];
	} *repl;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct args d;
	} sdata;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct repl d;
	} rdata;
	ssize_t cc;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv2_getrootfh: %s\n", path);
#endif

	args = &sdata.d;
	repl = &rdata.d;

	(void)memset(args, 0, sizeof(*args));
	len = strlen(path);
	if ((size_t)len > sizeof(args->path))
		len = sizeof(args->path);
	args->len = htonl(len);
	(void)memcpy(args->path, path, len);
	len = 4 + roundup(len, 4);

	cc = rpc_call(d, RPCPROG_MNT, RPCMNT_VER1, RPCMNT_MOUNT,
	    args, len, repl, sizeof(*repl));
	if (cc == -1) {
		/* errno was set by rpc_call */
		return -1;
	}
	if (cc < 4) {
		errno = EBADRPC;
		return -1;
	}
	if (repl->errno) {
		errno = ntohl(repl->errno);
		return -1;
	}
	(void)memcpy(fhp, repl->fh, sizeof(repl->fh));
	return 0;
}

/*
 * Lookup a file.  Store handle and attributes.
 * Return zero or error number.
 */
static int
nfsv2_lookupfh(struct nfs_iodesc *d, const char *name, int len,
	struct nfs_iodesc *newfd)
{
	int rlen;
	struct args {
		u_char	fh[NFS_FHSIZE];
		n_long	len;
		char	name[FNAME_SIZE];
	} *args;
	struct repl {
		n_long	errno;
		u_char	fh[NFS_FHSIZE];
		struct	nfsv2_fattrs fa;
	} *repl;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct args d;
	} sdata;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct repl d;
	} rdata;
	ssize_t cc;

#ifdef NFS_DEBUG
	if (debug)
		printf("lookupfh: called\n");
#endif

	args = &sdata.d;
	repl = &rdata.d;

	(void)memset(args, 0, sizeof(*args));
	(void)memcpy(args->fh, d->fh, sizeof(args->fh));
	if ((size_t)len > sizeof(args->name))
		len = sizeof(args->name);
	(void)memcpy(args->name, name, len);
	args->len = htonl(len);
	len = 4 + roundup(len, 4);
	len += NFS_FHSIZE;

	rlen = sizeof(*repl);

	cc = rpc_call(d->iodesc, NFS_PROG, NFS_VER2, NFSPROC_LOOKUP,
	    args, len, repl, rlen);
	if (cc == -1)
		return errno;		/* XXX - from rpc_call */
	if (cc < 4)
		return EIO;
	if (repl->errno) {
		/* saerrno.h now matches NFS error numbers. */
		return ntohl(repl->errno);
	}
	(void)memcpy(&newfd->fh, repl->fh, sizeof(repl->fh));
	(void)memcpy(&newfd->fa, &repl->fa, sizeof(repl->fa));
	return 0;
}

#ifndef NFS_NOSYMLINK
/*
 * Get the destination of a symbolic link.
 */
static int
nfsv2_readlink(struct nfs_iodesc *d, char *buf)
{
	struct nfs_readlnk_repl {
		n_long	errno;
		n_long	len;
		char	path[NFS_MAXPATHLEN];
	};
	struct {
		n_long	h[RPC_HEADER_WORDS];
		u_char fh[NFS_FHSIZE];
	} sdata;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct nfs_readlnk_repl d;
	} rdata;
	ssize_t cc;

#ifdef NFS_DEBUG
	if (debug)
		printf("readlink: called\n");
#endif

	(void)memcpy(sdata.fh, d->fh, NFS_FHSIZE);
	cc = rpc_call(d->iodesc, NFS_PROG, NFS_VER2, NFSPROC_READLINK,
	              sdata.fh, NFS_FHSIZE,
	              &rdata.d, sizeof(rdata.d));
	if (cc == -1)
		return errno;

	if (cc < 4)
		return EIO;

	if (rdata.d.errno)
		return ntohl(rdata.d.errno);

	rdata.d.len = ntohl(rdata.d.len);
	if (rdata.d.len > NFS_MAXPATHLEN)
		return ENAMETOOLONG;

	(void)memcpy(buf, rdata.d.path, rdata.d.len);
	buf[rdata.d.len] = 0;
	return 0;
}
#endif

/*
 * Read data from a file.
 * Return transfer count or -1 (and set errno)
 */
static ssize_t
nfsv2_readdata(struct nfs_iodesc *d, off_t off, void *addr, size_t len)
{
	struct nfs_read_args {
		u_char	fh[NFS_FHSIZE];
		n_long	off;
		n_long	len;
		n_long	xxx;			/* XXX what's this for? */
	} *args;
	struct nfs_read_repl {
		n_long	errno;
		struct	nfsv2_fattrs fa;
		n_long	count;
		u_char	data[NFSREAD_MIN_SIZE];
	} *repl;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct nfs_read_args d;
	} sdata;
	struct {
		n_long	h[RPC_HEADER_WORDS];
		struct nfs_read_repl d;
	} rdata;
	ssize_t cc;
	long x;
	size_t hlen, rlen;

	args = &sdata.d;
	repl = &rdata.d;

	(void)memcpy(args->fh, d->fh, NFS_FHSIZE);
	args->off = htonl((n_long)off);
	if (len > NFSREAD_MIN_SIZE)
		len = NFSREAD_MIN_SIZE;
	args->len = htonl((n_long)len);
	args->xxx = htonl((n_long)0);
	hlen = sizeof(*repl) - NFSREAD_MIN_SIZE;

	cc = rpc_call(d->iodesc, NFS_PROG, NFS_VER2, NFSPROC_READ,
	    args, sizeof(*args),
	    repl, sizeof(*repl));
	if (cc == -1) {
		/* errno was already set by rpc_call */
		return -1;
	}
	if (cc < (ssize_t)hlen) {
		errno = EBADRPC;
		return -1;
	}
	if (repl->errno) {
		errno = ntohl(repl->errno);
		return -1;
	}
	rlen = cc - hlen;
	x = ntohl(repl->count);
	if (rlen < (size_t)x) {
		printf("nfsread: short packet, %lu < %ld\n", (u_long) rlen, x);
		errno = EBADRPC;
		return -1;
	}
	(void)memcpy(addr, repl->data, x);
	return x;
}

/*
 * nfs_mount - mount this nfs filesystem to a host
 * On error, return non-zero and set errno.
 */
int
nfsv2_mount(int sock, struct in_addr ip, char *path)
{
	struct iodesc *desc;
	struct nfsv2_fattrs *fa;

	if (!(desc = socktodesc(sock))) {
		errno = EINVAL;
		return -1;
	}

	/* Bind to a reserved port. */
	desc->myport = htons(--rpc_port);
	desc->destip = ip;
	if (nfsv2_getrootfh(desc, path, nfs_root_node.fh))
		return -1;
	nfs_root_node.iodesc = desc;
	/* Fake up attributes for the root dir. */
	fa = &nfs_root_node.fa.v2;
	fa->fa_type  = htonl(NFDIR);
	fa->fa_mode  = htonl(0755);
	fa->fa_nlink = htonl(2);

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv2_mount: got fh for %s\n", path);
#endif

	return 0;
}

/*
 * Open a file.
 * return zero or error number
 */
__compactcall int
nfsv2_open(const char *path, struct open_file *f)
{
	struct nfs_iodesc *newfd, *currfd;
	const char *cp;
#ifndef NFS_NOSYMLINK
	const char *ncp;
	int c;
	char namebuf[NFS_MAXPATHLEN + 1];
	char linkbuf[NFS_MAXPATHLEN + 1];
	int nlinks = 0;
#endif
	int error = 0;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv2_open: %s\n", path);
#endif
#ifdef NFS_MOUNT_WHEN_OPEN
	if (!rootpath[0]) {
		printf("no rootpath, no nfs\n");
		return ENXIO;
	}

	if (nfsv2_mount(*(int *)(f->f_devdata), rootip, rootpath) == -1)
		return errno;
#else
	if (nfs_root_node.iodesc == NULL) {
		printf("nfsv2_open: must mount first.\n");
		return ENXIO;
	}
#endif

	currfd = &nfs_root_node;
	newfd = 0;

#ifndef NFS_NOSYMLINK
	cp = path;
	while (*cp) {
		/*
		 * Remove extra separators
		 */
		while (*cp == '/')
			cp++;

		if (*cp == '\0')
			break;
		/*
		 * Check that current node is a directory.
		 */
		if (currfd->fa.v2.fa_type != htonl(NFDIR)) {
			error = ENOTDIR;
			goto out;
		}

		/* allocate file system specific data structure */
		newfd = alloc(sizeof(*newfd));
		newfd->iodesc = currfd->iodesc;
		newfd->off = 0;

		/*
		 * Get next component of path name.
		 */
		{
			int len = 0;

			ncp = cp;
			while ((c = *cp) != '\0' && c != '/') {
				if (++len > NFS_MAXNAMLEN) {
					error = ENOENT;
					goto out;
				}
				cp++;
			}
		}

		/* lookup a file handle */
		error = nfsv2_lookupfh(currfd, ncp, cp - ncp, newfd);
		if (error)
			goto out;

		/*
		 * Check for symbolic link
		 */
		if (newfd->fa.v2.fa_type == htonl(NFLNK)) {
			int link_len, len;

			error = nfsv2_readlink(newfd, linkbuf);
			if (error)
				goto out;

			link_len = strlen(linkbuf);
			len = strlen(cp);

			if (link_len + len > MAXPATHLEN
			    || ++nlinks > MAXSYMLINKS) {
				error = ENOENT;
				goto out;
			}

			(void)memcpy(&namebuf[link_len], cp, len + 1);
			(void)memcpy(namebuf, linkbuf, link_len);

			/*
			 * If absolute pathname, restart at root.
			 * If relative pathname, restart at parent directory.
			 */
			cp = namebuf;
			if (*cp == '/') {
				if (currfd != &nfs_root_node)
					dealloc(currfd, sizeof(*currfd));
				currfd = &nfs_root_node;
			}

			dealloc(newfd, sizeof(*newfd));
			newfd = 0;

			continue;
		}

		if (currfd != &nfs_root_node)
			dealloc(currfd, sizeof(*currfd));
		currfd = newfd;
		newfd = 0;
	}

	error = 0;

out:
#else
	/* allocate file system specific data structure */
	currfd = alloc(sizeof(*currfd));
	currfd->iodesc = nfs_root_node.iodesc;
	currfd->off = 0;

	cp = path;
	/*
	 * Remove extra separators
	 */
	while (*cp == '/')
		cp++;

	/* XXX: Check for empty path here? */

	error = nfsv2_lookupfh(&nfs_root_node, cp, strlen(cp), currfd);
#endif
	if (!error) {
		f->f_fsdata = (void *)currfd;
		fsmod = "nfs";
		return 0;
	}

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv2_open: %s lookupfh failed: %s\n",
		    path, strerror(error));
#endif
	if (currfd != &nfs_root_node)
		dealloc(currfd, sizeof(*currfd));
	if (newfd)
		dealloc(newfd, sizeof(*newfd));

	return error;
}

__compactcall int
nfsv2_close(struct open_file *f)
{
	struct nfs_iodesc *fp = (struct nfs_iodesc *)f->f_fsdata;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv2_close: fp=0x%lx\n", (u_long)fp);
#endif

	if (fp)
		dealloc(fp, sizeof(struct nfs_iodesc));
	f->f_fsdata = (void *)0;

	return 0;
}

/*
 * read a portion of a file
 */
__compactcall int
nfsv2_read(struct open_file *f, void *buf, size_t size, size_t *resid)
{
	struct nfs_iodesc *fp = (struct nfs_iodesc *)f->f_fsdata;
	ssize_t cc;
	char *addr = buf;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv2_read: size=%lu off=%d\n", (u_long)size,
		    (int)fp->off);
#endif
	while ((int)size > 0) {
#if !defined(LIBSA_NO_TWIDDLE)
		twiddle();
#endif
		cc = nfsv2_readdata(fp, fp->off, (void *)addr, size);
		/* XXX maybe should retry on certain errors */
		if (cc == -1) {
#ifdef NFS_DEBUG
			if (debug)
				printf("nfsv2_read: read: %s\n",
				       strerror(errno));
#endif
			return errno;	/* XXX - from nfsv2_readdata */
		}
		if (cc == 0) {
#ifdef NFS_DEBUG
			if (debug)
				printf("nfsv2_read: hit EOF unexpectantly\n");
#endif
			goto ret;
		}
		fp->off += cc;
		addr += cc;
		size -= cc;
	}
ret:
	if (resid)
		*resid = size;

	return 0;
}

/*
 * Not implemented.
 */
__compactcall int
nfsv2_write(struct open_file *f, void *buf, size_t size, size_t *resid)
{
	return EROFS;
}

__compactcall off_t
nfsv2_seek(struct open_file *f, off_t offset, int where)
{
	struct nfs_iodesc *d = (struct nfs_iodesc *)f->f_fsdata;
	n_long size = ntohl(d->fa.v2.fa_size);

	switch (where) {
	case SEEK_SET:
		d->off = offset;
		break;
	case SEEK_CUR:
		d->off += offset;
		break;
	case SEEK_END:
		d->off = size - offset;
		break;
	default:
		return -1;
	}

	return d->off;
}

__compactcall int
nfsv2_stat(struct open_file *f, struct stat *sb)
{
	struct nfs_iodesc *fp = (struct nfs_iodesc *)f->f_fsdata;
	n_long ftype, mode;

	ftype = ntohl(fp->fa.v2.fa_type);
	mode  = ntohl(fp->fa.v2.fa_mode);
	mode |= nfs_stat_types[ftype & 7];

	sb->st_mode  = mode;
	sb->st_nlink = ntohl(fp->fa.v2.fa_nlink);
	sb->st_uid   = ntohl(fp->fa.v2.fa_uid);
	sb->st_gid   = ntohl(fp->fa.v2.fa_gid);
	sb->st_size  = ntohl(fp->fa.v2.fa_size);

	return 0;
}

#if defined(LIBSA_ENABLE_LS_OP)
#include "ls.h"
__compactcall void
nfsv2_ls(struct open_file *f, const char *pattern)
{
	lsunsup("nfs");
}
#endif
#endif /* !NFS_V3_ONLY */

#ifndef NFS_V2_ONLY
/*
 * NFS v3
 */

FS_DEF(nfsv3);
int nfsv3_mount(int, struct in_addr, char *);

#ifdef __FBSDID
__FBSDID("$FreeBSD: head/stand/libsa/nfs.c 337039 2018-08-01 12:14:10Z tsoome $");
#endif

static int nfs_read_size = NFSREAD_MIN_SIZE;

/*
 * Fetch the root file handle (call mount daemon)
 * On error, return non-zero and set errno.
 */
static int
nfsv3_getrootfh(struct iodesc *d, char *path, uint32_t *fhlenp, u_char *fhp)
{
	int len;
	struct args {
		uint32_t len;
		char path[FNAME_SIZE];
	} *args;
	struct repl {
		uint32_t errno;
		uint32_t fhsize;
		u_char fh[NFS_V3MAXFHSIZE];
		uint32_t authcnt;
		uint32_t auth[7];
	} *repl;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct args d;
	} sdata;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct repl d;
	} rdata;
	ssize_t cc;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv3_getrootfh: %s\n", path);
#endif

	args = &sdata.d;
	repl = &rdata.d;

	(void)memset(args, 0, sizeof(*args));
	len = strlen(path);
	if ((size_t)len > sizeof(args->path))
		len = sizeof(args->path);
	args->len = htonl(len);
	(void)memcpy(args->path, path, len);
	len = sizeof(uint32_t) + roundup(len, sizeof(uint32_t));

	cc = rpc_call(d, RPCPROG_MNT, RPCMNT_VER3, RPCMNT_MOUNT,
	    args, len, repl, sizeof(*repl));
	if (cc == -1) {
		/* errno was set by rpc_call */
		return -1;
	}
	if (cc < 2 * sizeof(uint32_t)) {
		errno = EBADRPC;
		return -1;
	}
	if (repl->errno) {
		errno = ntohl(repl->errno);
		return -1;
	}
	*fhlenp = ntohl(repl->fhsize);
	(void)memcpy(fhp, repl->fh, *fhlenp);
	return 0;
}

/*
 * Lookup a file.  Store handle and attributes.
 * Return zero or error number.
 */
static int
nfsv3_lookupfh(struct nfs_iodesc *d, const char *name, int len,
	struct nfs_iodesc *newfd)
{
	int pos;
	struct args {
		uint32_t fhsize;
		uint32_t fhplusname[1 +
		    (NFS_V3MAXFHSIZE + FNAME_SIZE) / sizeof(uint32_t)];
	} *args;
	struct repl {
		uint32_t errno;
		uint32_t fhsize;
		uint32_t fhplusattr[(NFS_V3MAXFHSIZE +
		    2 * (sizeof(uint32_t) +
		    sizeof(struct nfsv3_fattrs))) / sizeof(uint32_t)];
	} *repl;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct args d;
	} sdata;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct repl d;
	} rdata;
	ssize_t cc;

#ifdef NFS_DEBUG
	if (debug)
		printf("lookupfh: called\n");
#endif

	args = &sdata.d;
	repl = &rdata.d;

	(void)memset(args, 0, sizeof(*args));
	args->fhsize = htonl(d->fhsize);
	(void)memcpy(args->fhplusname, d->fh, d->fhsize);
	if (len > FNAME_SIZE)
		len = FNAME_SIZE;
	pos = roundup(d->fhsize, sizeof(uint32_t)) / sizeof(uint32_t);
	args->fhplusname[pos++] = htonl(len);
	(void)memcpy(&args->fhplusname[pos], name, len);
	len = sizeof(uint32_t) + pos * sizeof(uint32_t) +
	    roundup(len, sizeof(uint32_t));

	cc = rpc_call(d->iodesc, NFS_PROG, NFS_VER3, NFSPROCV3_LOOKUP,
	    args, len, repl, sizeof(*repl));
	if (cc == -1)
		return errno;		/* XXX - from rpc_call */
	if (cc < 2 * sizeof(uint32_t))
		return EIO;
	if (repl->errno) {
		/* saerrno.h now matches NFS error numbers. */
		return ntohl(repl->errno);
	}
	newfd->fhsize = ntohl(repl->fhsize);
	(void)memcpy(&newfd->fh, repl->fhplusattr, newfd->fhsize);
	pos = roundup(newfd->fhsize, sizeof(uint32_t)) / sizeof(uint32_t);
	if (repl->fhplusattr[pos++] == 0)
		return EIO;
	(void)memcpy(&newfd->fa, &repl->fhplusattr[pos], sizeof(newfd->fa.v3));
	return 0;
}

#ifndef NFS_NOSYMLINK
/*
 * Get the destination of a symbolic link.
 */
static int
nfsv3_readlink(struct nfs_iodesc *d, char *buf)
{
	struct args {
		uint32_t fhsize;
		u_char fh[NFS_V3MAXFHSIZE];
	} *args;
	struct repl {
		uint32_t errno;
		uint32_t ok;
		struct nfsv3_fattrs fa;
		uint32_t len;
		u_char path[NFS_MAXPATHLEN];
	} *repl;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct args d;
	} sdata;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct repl d;
	} rdata;
	ssize_t cc;

#ifdef NFS_DEBUG
	if (debug)
		printf("readlink: called\n");
#endif

	args = &sdata.d;
	repl = &rdata.d;

	(void)memset(args, 0, sizeof(*args));
	args->fhsize = htonl(d->fhsize);
	(void)memcpy(args->fh, d->fh, d->fhsize);
	cc = rpc_call(d->iodesc, NFS_PROG, NFS_VER3, NFSPROCV3_READLINK,
	    args, sizeof(uint32_t) + roundup(d->fhsize, sizeof(uint32_t)),
	    repl, sizeof(*repl));
	if (cc == -1)
		return errno;

	if (cc < 2 * sizeof(uint32_t))
		return EIO;

	if (repl->errno)
		return ntohl(repl->errno);

	if (!repl->ok)
		return EIO;

	repl->len = ntohl(repl->len);
	if (repl->len > NFS_MAXPATHLEN)
		return ENAMETOOLONG;

	(void)memcpy(buf, repl->path, repl->len);
	buf[repl->len] = 0;
	return 0;
}
#endif

/*
 * Read data from a file.
 * Return transfer count or -1 (and set errno)
 */
static ssize_t
nfsv3_readdata(struct nfs_iodesc *d, off_t off, void *addr, size_t len)
{
	struct args {
		uint32_t fhsize;
		uint32_t fhoffcnt[NFS_V3MAXFHSIZE / sizeof(uint32_t) + 3];
	} *args;
	struct repl {
		uint32_t errno;
		uint32_t ok;
		struct nfsv3_fattrs fa;
		uint32_t count;
		uint32_t eof;
		uint32_t len;
		u_char data[NFSREAD_MAX_SIZE];
	} *repl;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct args d;
	} sdata;
	struct {
		uint32_t h[RPC_HEADER_WORDS];
		struct repl d;
	} rdata;
	ssize_t cc;
	long x;
	size_t hlen, rlen, pos;

	args = &sdata.d;
	repl = &rdata.d;

	(void)memset(args, 0, sizeof(*args));
	args->fhsize = htonl(d->fhsize);
	(void)memcpy(args->fhoffcnt, d->fh, d->fhsize);
	pos = roundup(d->fhsize, sizeof(uint32_t)) / sizeof(uint32_t);
	args->fhoffcnt[pos++] = 0;
	args->fhoffcnt[pos++] = htonl((uint32_t)off);
	if (len > nfs_read_size)
		len = nfs_read_size;
	args->fhoffcnt[pos] = htonl((uint32_t)len);
	hlen = offsetof(struct repl, data[0]);

	cc = rpc_call(d->iodesc, NFS_PROG, NFS_VER3, NFSPROCV3_READ,
	    args, 4 * sizeof(uint32_t) + roundup(d->fhsize, sizeof(uint32_t)),
	    repl, sizeof(*repl));
	if (cc == -1) {
		/* errno was already set by rpc_call */
		return -1;
	}
	if (cc < (ssize_t)hlen) {
		errno = EBADRPC;
		return -1;
	}
	if (repl->errno) {
		errno = ntohl(repl->errno);
		return -1;
	}
	rlen = cc - hlen;
	x = ntohl(repl->count);
	if (rlen < (size_t)x) {
		printf("nfsread: short packet, %lu < %ld\n", (u_long) rlen, x);
		errno = EBADRPC;
		return -1;
	}
	(void)memcpy(addr, repl->data, x);
	return x;
}

/*
 * nfs_mount - mount this nfs filesystem to a host
 * On error, return non-zero and set errno.
 */
int
nfsv3_mount(int sock, struct in_addr ip, char *path)
{
	struct iodesc *desc;
	struct nfsv3_fattrs *fa;

	if (!(desc = socktodesc(sock))) {
		errno = EINVAL;
		return -1;
	}

	/* Bind to a reserved port. */
	desc->myport = htons(--rpc_port);
	desc->destip = ip;
	if (nfsv3_getrootfh(desc, path, &nfs_root_node.fhsize,
	    nfs_root_node.fh))
		return -1;
	nfs_root_node.iodesc = desc;
	/* Fake up attributes for the root dir. */
	fa = &nfs_root_node.fa.v3;
	fa->fa_type  = htonl(NFDIR);
	fa->fa_mode  = htonl(0755);
	fa->fa_nlink = htonl(2);

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv3_mount: got fh for %s\n", path);
#endif

	return 0;
}

/*
 * Open a file.
 * return zero or error number
 */
__compactcall int
nfsv3_open(const char *path, struct open_file *f)
{
	struct nfs_iodesc *newfd, *currfd;
	const char *cp;
#ifndef NFS_NOSYMLINK
	const char *ncp;
	int c;
	char namebuf[NFS_MAXPATHLEN + 1];
	char linkbuf[NFS_MAXPATHLEN + 1];
	int nlinks = 0;
#endif
	int error = 0;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv3_open: %s\n", path);
#endif
#ifdef NFS_MOUNT_WHEN_OPEN
	if (!rootpath[0]) {
		printf("no rootpath, no nfs\n");
		return ENXIO;
	}

	if (nfsv3_mount(*(int *)(f->f_devdata), rootip, rootpath) == -1)
		return errno;
#else
	if (nfs_root_node.iodesc == NULL) {
		printf("nfsv3_open: must mount first.\n");
		return ENXIO;
	}
#endif

	currfd = &nfs_root_node;
	newfd = 0;

#ifndef NFS_NOSYMLINK
	cp = path;
	while (*cp) {
		/*
		 * Remove extra separators
		 */
		while (*cp == '/')
			cp++;

		if (*cp == '\0')
			break;
		/*
		 * Check that current node is a directory.
		 */
		if (currfd->fa.v3.fa_type != htonl(NFDIR)) {
			error = ENOTDIR;
			goto out;
		}

		/* allocate file system specific data structure */
		newfd = alloc(sizeof(*newfd));
		newfd->iodesc = currfd->iodesc;
		newfd->off = 0;

		/*
		 * Get next component of path name.
		 */
		{
			int len = 0;

			ncp = cp;
			while ((c = *cp) != '\0' && c != '/') {
				if (++len > NFS_MAXNAMLEN) {
					error = ENOENT;
					goto out;
				}
				cp++;
			}
		}

		/* lookup a file handle */
		error = nfsv3_lookupfh(currfd, ncp, cp - ncp, newfd);
		if (error)
			goto out;

		/*
		 * Check for symbolic link
		 */
		if (newfd->fa.v3.fa_type == htonl(NFLNK)) {
			int link_len, len;

			error = nfsv3_readlink(newfd, linkbuf);
			if (error)
				goto out;

			link_len = strlen(linkbuf);
			len = strlen(cp);

			if (link_len + len > MAXPATHLEN
			    || ++nlinks > MAXSYMLINKS) {
				error = ENOENT;
				goto out;
			}

			(void)memcpy(&namebuf[link_len], cp, len + 1);
			(void)memcpy(namebuf, linkbuf, link_len);

			/*
			 * If absolute pathname, restart at root.
			 * If relative pathname, restart at parent directory.
			 */
			cp = namebuf;
			if (*cp == '/') {
				if (currfd != &nfs_root_node)
					dealloc(currfd, sizeof(*currfd));
				currfd = &nfs_root_node;
			}

			dealloc(newfd, sizeof(*newfd));
			newfd = 0;

			continue;
		}

		if (currfd != &nfs_root_node)
			dealloc(currfd, sizeof(*currfd));
		currfd = newfd;
		newfd = 0;
	}

	error = 0;

out:
#else
	/* allocate file system specific data structure */
	currfd = alloc(sizeof(*currfd));
	currfd->iodesc = nfs_root_node.iodesc;
	currfd->off = 0;

	cp = path;
	/*
	 * Remove extra separators
	 */
	while (*cp == '/')
		cp++;

	/* XXX: Check for empty path here? */

	error = nfsv3_lookupfh(&nfs_root_node, cp, strlen(cp), currfd);
#endif
	if (!error) {
		f->f_fsdata = (void *)currfd;
		fsmod = "nfs";
		return 0;
	}

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv3_open: %s lookupfh failed: %s\n",
		    path, strerror(error));
#endif
	if (currfd != &nfs_root_node)
		dealloc(currfd, sizeof(*currfd));
	if (newfd)
		dealloc(newfd, sizeof(*newfd));

	return error;
}

__compactcall int
nfsv3_close(struct open_file *f)
{
	struct nfs_iodesc *fp = (struct nfs_iodesc *)f->f_fsdata;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv3_close: fp=0x%lx\n", (u_long)fp);
#endif

	if (fp)
		dealloc(fp, sizeof(struct nfs_iodesc));
	f->f_fsdata = (void *)0;

	return 0;
}

/*
 * read a portion of a file
 */
__compactcall int
nfsv3_read(struct open_file *f, void *buf, size_t size, size_t *resid)
{
	struct nfs_iodesc *fp = (struct nfs_iodesc *)f->f_fsdata;
	ssize_t cc;
	char *addr = buf;

#ifdef NFS_DEBUG
	if (debug)
		printf("nfsv3_read: size=%lu off=%d\n", (u_long)size,
		    (int)fp->off);
#endif
	while ((int)size > 0) {
#if !defined(LIBSA_NO_TWIDDLE)
		twiddle();
#endif
		cc = nfsv3_readdata(fp, fp->off, (void *)addr, size);
		/* XXX maybe should retry on certain errors */
		if (cc == -1) {
#ifdef NFS_DEBUG
			if (debug)
				printf("nfsv3_read: read: %s\n",
				       strerror(errno));
#endif
			return errno;	/* XXX - from nfsv3_readdata */
		}
		if (cc == 0) {
#ifdef NFS_DEBUG
			if (debug)
				printf("nfsv3_read: hit EOF unexpectantly\n");
#endif
			goto ret;
		}
		fp->off += cc;
		addr += cc;
		size -= cc;
	}
ret:
	if (resid)
		*resid = size;

	return 0;
}

/*
 * Not implemented.
 */
__compactcall int
nfsv3_write(struct open_file *f, void *buf, size_t size, size_t *resid)
{
	return EROFS;
}

__compactcall off_t
nfsv3_seek(struct open_file *f, off_t offset, int where)
{
	struct nfs_iodesc *d = (struct nfs_iodesc *)f->f_fsdata;
	uint32_t size = ntohl(d->fa.v3.fa_size.val[1]);

	switch (where) {
	case SEEK_SET:
		d->off = offset;
		break;
	case SEEK_CUR:
		d->off += offset;
		break;
	case SEEK_END:
		d->off = size - offset;
		break;
	default:
		return -1;
	}

	return d->off;
}

__compactcall int
nfsv3_stat(struct open_file *f, struct stat *sb)
{
	struct nfs_iodesc *fp = (struct nfs_iodesc *)f->f_fsdata;
	uint32_t ftype, mode;

	ftype = ntohl(fp->fa.v3.fa_type);
	mode  = ntohl(fp->fa.v3.fa_mode);
	mode |= nfs_stat_types[ftype & 7];

	sb->st_mode  = mode;
	sb->st_nlink = ntohl(fp->fa.v3.fa_nlink);
	sb->st_uid   = ntohl(fp->fa.v3.fa_uid);
	sb->st_gid   = ntohl(fp->fa.v3.fa_gid);
	sb->st_size  = ntohl(fp->fa.v3.fa_size.val[1]);

	return 0;
}

#if defined(LIBSA_ENABLE_LS_OP)
#include "ls.h"
__compactcall void
nfsv3_ls(struct open_file *f, const char *pattern)
{
	lsunsup("nfs");
}
#endif
#endif /* !NFS_V2_ONLY */

#if defined(NFS_V2_ONLY)
__strong_alias(nfs_mount, nfsv2_mount);
__strong_alias(nfs_open, nfsv2_open);
__strong_alias(nfs_close, nfsv2_close);
__strong_alias(nfs_read, nfsv2_read);
__strong_alias(nfs_write, nfsv2_write);
__strong_alias(nfs_seek, nfsv2_seek);
__strong_alias(nfs_stat, nfsv2_stat);
__strong_alias(nfs_ls, nfsv2_ls);
#elif defined(NFS_V3_ONLY)
__strong_alias(nfs_mount, nfsv3_mount);
__strong_alias(nfs_open, nfsv3_open);
__strong_alias(nfs_close, nfsv3_close);
__strong_alias(nfs_read, nfsv3_read);
__strong_alias(nfs_write, nfsv3_write);
__strong_alias(nfs_seek, nfsv3_seek);
__strong_alias(nfs_stat, nfsv3_stat);
__strong_alias(nfs_ls, nfsv3_ls);
#else
struct nfs_ops {
	__compactcall int	(*open)(const char *, struct open_file *);
	__compactcall int	(*close)(struct open_file *);
	__compactcall int	(*read)(struct open_file *, void *, size_t,
				    size_t *);
	__compactcall int	(*write)(struct open_file *, void *, size_t,
				    size_t *);
	__compactcall off_t	(*seek)(struct open_file *, off_t, int);
	__compactcall int	(*stat)(struct open_file *, struct stat *);
#if defined(LIBSA_ENABLE_LS_OP)
	__compactcall void	(*ls)(struct open_file *, const char *);
#endif
};

static const struct nfs_ops *nfs_ops;
static const struct nfs_ops nfsv2_ops = {
	.open = nfsv2_open,
	.close = nfsv2_close,
	.read = nfsv2_read,
	.write = nfsv2_write,
	.seek = nfsv2_seek,
	.stat = nfsv2_stat,
#if defined(LIBSA_ENABLE_LS_OP)
	.ls = nfsv2_ls,
#endif
};
static const struct nfs_ops nfsv3_ops = {
	.open = nfsv3_open,
	.close = nfsv3_close,
	.read = nfsv3_read,
	.write = nfsv3_write,
	.seek = nfsv3_seek,
	.stat = nfsv3_stat,
#if defined(LIBSA_ENABLE_LS_OP)
	.ls = nfsv3_ls,
#endif
};

int
nfs_mount(int sock, struct in_addr ip, char *path)
{

	if (nfsv3_mount(sock, ip, path) == 0) {
		nfs_ops = &nfsv3_ops;
		return 0;
	} else if (nfsv2_mount(sock, ip, path) == 0) {
		nfs_ops = &nfsv2_ops;
		return 0;
	}
	return -1;
}

__compactcall int
nfs_open(const char *path, struct open_file *f)
{

#ifdef NFS_DEBUG
	if (debug)
		printf("nfs_open: %s\n", path);
#endif
#ifdef NFS_MOUNT_WHEN_OPEN
	if (!rootpath[0]) {
		printf("no rootpath, no nfs\n");
		return ENXIO;
	}

	if (nfsv3_mount(*(int *)(f->f_devdata), rootip, rootpath) == -1 &&
	    nfsv2_mount(*(int *)(f->f_devdata), rootip, rootpath) == -1)
		return errno;
#else
	if (nfs_root_node.iodesc == NULL) {
		printf("nfs_open: must mount first.\n");
		return ENXIO;
	}
#endif

	return (*nfs_ops->open)(path, f);
}

__compactcall int
nfs_close(struct open_file *f)
{

	if (nfs_ops == NULL)
		return ENXIO;

	return (*nfs_ops->close)(f);
}

__compactcall int
nfs_read(struct open_file *f, void *buf, size_t size, size_t *resid)
{

	if (nfs_ops == NULL)
		return ENXIO;

	return (*nfs_ops->read)(f, buf, size, resid);
}

__compactcall int
nfs_write(struct open_file *f, void *buf, size_t size, size_t *resid)
{

	if (nfs_ops == NULL)
		return ENXIO;

	return (*nfs_ops->write)(f, buf, size, resid);
}

__compactcall off_t
nfs_seek(struct open_file *f, off_t offset, int where)
{

	if (nfs_ops == NULL) {
		errno = ENXIO;
		return -1;
	}

	return (*nfs_ops->seek)(f, offset, where);
}

__compactcall int
nfs_stat(struct open_file *f, struct stat *sb)
{

	if (nfs_ops == NULL)
		return ENXIO;

	return (*nfs_ops->stat)(f, sb);
}

#if defined(LIBSA_ENABLE_LS_OP)
__compactcall void
nfs_ls(struct open_file *f, const char *pattern)
{
	if (nfs_ops == NULL)
		return;

	(*nfs_ops->ls)(f, pattern);
}
#endif
#endif /* !NFS_V2_ONLY && !NFS_V3_ONLY */
