/*	$NetBSD$	*/

#include <sys/param.h>
#include <sys/bootblock.h>
#include <sys/dkio.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "libgeom.h"
#include "partutil.h"

static int	fakegeom_make(struct gmesh *);
static void	fakegeom_free(struct gmesh *);

int
geom_gettree(struct gmesh *mesh)
{

	return fakegeom_make(mesh);
}

void
geom_deletetree(struct gmesh *mesh)
{

	fakegeom_free(mesh);
}

char *
g_device_path(const char *devpath)
{
	char buf[MAXPATHLEN];
	u_int secsz;
	int fd, error;

	fd = opendisk(devpath, O_RDONLY, buf, sizeof(buf), 1);
	if (fd == -1)
		return NULL;

	/* Let try to get sectorsize, which will prove it is a disk device. */
	error = ioctl(fd, DIOCGSECTORSIZE, &secsz);
	close(fd);
	if (error == -1) {
		errno = EFTYPE;
		return NULL;
	}
	return strdup(buf);
}

/*
 * internal functions
 */

#if 0
/* http://phk.freebsd.dk/pubs/bsdcan-04.slides.geomtut.pdf */
/*
“A class”
– An implementation of a particular transformation.
 ● MBR (partitioning)
 ● BSD (ditto)
 ● Mirroring
 ● RAID-5
*/
/*
“A geom”  (NB: lower case)
– An instance of a class.
 ● “the MBR which partitions the ad0 device”
 ● “the BSD which partitions the ad0s1 device”
 ● “the MIRROR which mirrors the ad2 and ad3 devices”
*/
/*
“A Provider”
– A service point offered by a geom.
– Corresponds loosely to “/dev entry”
 ● ad0
 ● ad0s1
 ● ad0s1a
 ● ad0.ad1.mirror
*/

/*
“A consumer”
– The hook which a geom attach to a provider.
– name­less, but not anonymous.
*/

/*
Topology limits:
● A geom can have 0..N consumers
● A geom can have 0..N providers.
● A consumer can be attached to a single provider.
● A provider can have many consumers attached.
● Topology must be a strictly directed graph.
 – No loops allowed.
*/
#endif

#define G_DISK	"DISK"
#define G_PART	"PART"
#define G_LABEL	"LABEL"
#define G_DEV	"DEV"
#define G_RAID	"RAID"

#include "map.h"
#include "gpt.h"
#include "gpt_private.h"

#if 0
struct diskinfo;
SIMPLEQ_HEAD(diskinfohead, diskinfo);

typedef enum {
	PARTTYPE_MBR,
	PARTTYPE_GPT,
	PARTTYPE_UNKNOWN = -1
} parttype_t;

struct diskinfo {
	char name[16];
	parttype_t type;
	int64_t partno;
	char *efimedia;
	struct diskinfo *parent;
	struct dkwedge_info *dkw;
	gpt_t gpt;
	struct diskinfohead children;
	SIMPLEQ_ENTRY(diskinfo) node;
};

static const char *
get_mbr_dsn(void *data)
{
	static char buf[16];
	char *mbr = data;
	uint32_t dsn;

	dsn = le32dec(mbr + MBR_DSN_OFFSET);
	snprintf(buf, sizeof(buf), "%#08x", dsn);

	return buf;
}

static const char *
get_gpt_guid(void *data)
{
	static char guid[128];
	struct gpt_ent *ent = data;

	gpt_uuid_snprintf(guid, sizeof(guid), "%s", ent->ent_guid);

	return guid;
}

static int
get_disks(struct diskinfohead *head)
{
	static const int nodes[] = { CTL_HW, HW_DISKNAMES };
	struct diskinfo *di, *next;
	char *disknames, *p, *ep;
	size_t len, ndisks;
	int error;

	disknames = asysctl(nodes, __arraycount(nodes), &len);
	if (disknames == NULL)
		return errno;

	error = 0;
	for (p = strtok_r(disknames, " ", &ep), ndisks = 0;
	    p != NULL;
	    p = strtok_r(NULL, " ", &ep), ndisks++) {

		di = malloc(sizeof(*di));
		if (di == NULL) {
			error = errno;
			goto out;
		}

		strlcpy(di->name, p, sizeof(di->name));
		di->partno = -1;
		di->type = PARTTYPE_UNKNOWN;
		di->efimedia = NULL;
		di->parent = NULL;
		di->dkw = NULL;
		di->gpt = NULL;
		SIMPLEQ_INIT(&di->children);

		if (IS_DK(p))
			get_dkwedge_info(di);

		di->gpt = gpt_open(di->name, GPT_QUIET | GPT_READONLY, 0, 0, 0, 0);
		if (di->gpt != NULL)
			gpt_close(di->gpt);

		if (di->dkw == NULL && di->gpt == NULL) {
			free(di);
			continue;
		}

		SIMPLEQ_INSERT_TAIL(head, di, node);
	}

	SIMPLEQ_FOREACH_SAFE(di, head, node, next) {
		struct diskinfo *dkdi, *dknext;
		const struct map *m;

		if (di->gpt == NULL)
			continue;

		for (m = map_first(di->gpt); m != NULL; m = m->map_next) {
			if (m->map_type == MAP_TYPE_PRI_GPT_HDR ||
			    m->map_type == MAP_TYPE_SEC_GPT_HDR ||
			    m->map_type == MAP_TYPE_PRI_GPT_TBL ||
			    m->map_type == MAP_TYPE_SEC_GPT_TBL ||
			    m->map_type == MAP_TYPE_GPT_PART) {
				di->type = PARTTYPE_GPT;
				break;
			} else if (m->map_type == MAP_TYPE_MBR_PART) {
				di->type = PARTTYPE_MBR;
				break;
			}
		}

		SIMPLEQ_FOREACH_SAFE(dkdi, head, node, dknext) {
			if (dkdi == di ||
			    dkdi->dkw == NULL ||
			    strcmp(di->name, dkdi->dkw->dkw_parent) != 0)
				continue;

			for (m = map_first(di->gpt); m != NULL; m = m->map_next) {
				if (dkdi->dkw->dkw_offset == m->map_start &&
				    m->map_size >= 0 &&
				    dkdi->dkw->dkw_size == (uint64_t)m->map_size) {
					const char *type, *uniq;
					int nbytes;

					switch (m->map_type) {
					case MAP_TYPE_MBR_PART:
						type = "MBR";
						uniq = get_mbr_dsn(m->map_data);
						goto common;
					case MAP_TYPE_GPT_PART:
						type = "GPT";
						uniq = get_gpt_guid(m->map_data);
common:
						dkdi->type = di->type;
						dkdi->partno = m->map_index;
						dkdi->parent = di;

						nbytes = asprintf(&dkdi->efimedia,
						    "HD(%" PRIu64 ",%s,%s,"
						    "%#" PRIxMAX ",%#" PRIxMAX ")",
						    dkdi->partno, type, uniq,
						    (uintmax_t)m->map_start,
						    (intmax_t)m->map_size);
						if (nbytes == -1)
							break;

						next = SIMPLEQ_NEXT(dkdi, node);
						SIMPLEQ_REMOVE(head, dkdi, diskinfo,
						    node);
						SIMPLEQ_INSERT_TAIL(&di->children,
						    dkdi, node);
						break;
					}
				}
			}
		}
	}

out:
	free(disknames);
	return error;
}

static void
free_disks(struct diskinfohead *head)
{
	struct diskinfo *di, *next;

	SIMPLEQ_FOREACH_SAFE(di, head, node, next) {
		free_disks(&di->children);

		SIMPLEQ_REMOVE(head, di, diskinfo, node);
		if (di->efimedia != NULL)
			free(di->efimedia);
		if (di->dkw != NULL)
			free(di->dkw);
		if (di->gpt != NULL) {
			/* XXX: mediamap */
			free(di->gpt);
		}
		free(di);
	}
}

static void
print_diskinfo(struct diskinfohead *head, int depth)
{
	struct diskinfo *di;

	SIMPLEQ_FOREACH(di, head, node) {
		printf("%*s%s %s\n", depth, "", di->name,
		    di->efimedia != NULL ? di->efimedia : "");
		print_diskinfo(&di->children, depth + 1);
	}
}

int
main(void)
{
	struct diskinfohead head;
	int error;

	SIMPLEQ_INIT(&head);

	error = get_disks(&head);
	if (error == 0) {
		print_diskinfo(&head, 0);
		free_disks(&head);
	}

	return error == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
#endif

struct fakegeom_diskinfo {
	struct disk_geom geo;
	struct dkwedge_info dkw;
};

static const struct fakegeom_diskinfo *
fakegeom_get_diskinfo(const char *name)
{
	static struct diskinfo {
		char name[16];
		struct fakegeom_diskinfo diskinfo;
	} *diskinfo;
	static int n, alloced;
	char buf[MAXPATHLEN];
	int i, fd, error;

	if (diskinfo == NULL) {
		alloced = 8;
		error = reallocarr(&diskinfo, alloced, sizeof(*diskinfo));
		if (error != 0) {
			errno = error;
			return NULL;
		}
		n = 0;
	}

	for (i = 0; i < n; i++) {
		if (strcmp(name, diskinfo[i].name) == 0)
			break;
	}
	if (i < n)
		return &diskinfo[i].diskinfo;

	if (n == alloced) {
		alloced *= 2;
		error = reallocarr(&diskinfo, alloced, sizeof(*diskinfo));
		if (error != 0) {
			errno = error;
			return NULL;
		}
	}

	fd = opendisk(name, O_RDONLY, buf, sizeof(buf), 0);
	if (fd == -1)
		return NULL;

	error = getdiskinfo(name, fd, NULL, &diskinfo[i].diskinfo.geo,
	    &diskinfo[i].diskinfo.dkw);
	close(fd);
	if (error == -1)
		return NULL;

	strlcpy(diskinfo[i].name, name, sizeof(diskinfo[i].name));
	n++;

	return &diskinfo[i].diskinfo;
}

static void 
delete_config(struct gconf *gp)
{
	struct gconfig *cf;

	for (;;) {
		cf = LIST_FIRST(gp);
		if (cf == NULL)
			break;
		LIST_REMOVE(cf, lg_config);
		free(cf->lg_name);
		free(cf->lg_val);
		free(cf);
	}
}

static void
fakegeom_free(struct gmesh *gmp)
{
	struct gclass *cl;
	struct ggeom *ge;
	struct gprovider *pr;
	struct gconsumer *co;

	free(gmp->lg_ident);
	gmp->lg_ident = NULL;
	for (;;) {
		cl = LIST_FIRST(&gmp->lg_class);
		if (cl == NULL) 
			break;
		LIST_REMOVE(cl, lg_class);
		delete_config(&cl->lg_config);
		if (cl->lg_name != NULL)
			free(cl->lg_name);
		for (;;) {
			ge = LIST_FIRST(&cl->lg_geom);
			if (ge == NULL) 
				break;
			LIST_REMOVE(ge, lg_geom);
			delete_config(&ge->lg_config);
			if (ge->lg_name != NULL)
				free(ge->lg_name);
			for (;;) {
				pr = LIST_FIRST(&ge->lg_provider);
				if (pr == NULL) 
					break;
				LIST_REMOVE(pr, lg_provider);
				delete_config(&pr->lg_config);
				if (pr->lg_name != NULL)
					free(pr->lg_name);
				if (pr->lg_mode != NULL)
					free(pr->lg_mode);
				free(pr);
			}
			for (;;) {
				co = LIST_FIRST(&ge->lg_consumer);
				if (co == NULL) 
					break;
				LIST_REMOVE(co, lg_consumer);
				delete_config(&co->lg_config);
				if (co->lg_mode != NULL)
					free(co->lg_mode);
				free(co);
			}
			free(ge);
		}
		free(cl);
	}
}

static int
fakegeom_add_ident(struct gmesh *gmp, int what, void *ptr)
{
	int error;

	if (gmp->_lg_nident >= gmp->_lg_aident) {
		gmp->_lg_aident *= 2;
		error = reallocarr(&gmp->lg_ident, gmp->_lg_aident,
		    sizeof(*gmp->lg_ident));
		if (error != 0)
			return error;
	}

	gmp->lg_ident[gmp->_lg_nident].lg_id = NULL;
	gmp->lg_ident[gmp->_lg_nident].lg_ptr = ptr;
	gmp->lg_ident[gmp->_lg_nident].lg_what = what;
	gmp->_lg_nident++;

	return 0;
}

static struct gconfig *
fakegeom_add_gconfig(struct gconf *head, const char *name, const char *val)
{
	struct gconfig *cf;

	cf = malloc(sizeof(*cf));
	if (cf == NULL)
		return NULL;
	cf->lg_name = strdup(name);
	if (cf->lg_name == NULL) {
		free(cf);
		return NULL;
	}
	cf->lg_val = strdup(val);
	if (cf->lg_val == NULL) {
		free(cf->lg_name);
		free(cf);
		return NULL;
	}

	LIST_INSERT_HEAD(head, cf, lg_config);

	return cf;
}

static struct gconfig *
fakegeom_add_gconfig_uint(struct gconf *head, const char *name, uintmax_t value)
{
	struct gconfig *cf;
	char *p;
	int error;

	error = asprintf(&p, "%" PRIuMAX, value);
	if (error != 0) {
		errno = error;
		return NULL;
	}
	cf = fakegeom_add_gconfig(head, name, p);
	free(p);
	return cf;
}

static struct gclass *
fakegeom_add_gclass(struct gmesh *gmp, const char *name)
{
	struct gclass *cl;
	int error;

	cl = malloc(sizeof(*cl));
	if (cl == NULL)
		return NULL;
	cl->lg_id = NULL;
	cl->lg_name = strdup(name);
	if (cl->lg_name == NULL) {
		free(cl);
		return NULL;
	}
	LIST_INIT(&cl->lg_geom);
	LIST_INIT(&cl->lg_config);

	error = fakegeom_add_ident(gmp, ISCLASS, cl);
	if (error != 0) {
		free(cl->lg_name);
		free(cl);
		return NULL;
	}

	LIST_INSERT_HEAD(&gmp->lg_class, cl, lg_class);

	return cl;
}

static struct ggeom *
fakegeom_add_ggeom(struct gmesh *gmp, struct gclass *cl, const char *name,
    int rank)
{
	struct ggeom *ge;
	int error;

	ge = malloc(sizeof(*ge));
	if (ge == NULL)
		return NULL;
	ge->lg_id = NULL;
	ge->lg_name = strdup(name);
	if (ge->lg_name == NULL) {
		free(ge);
		return NULL;
	}
	ge->lg_rank = rank;
	LIST_INIT(&ge->lg_consumer);
	LIST_INIT(&ge->lg_provider);
	LIST_INIT(&ge->lg_config);

	error = fakegeom_add_ident(gmp, ISGEOM, ge);
	if (error != 0) {
		free(ge->lg_name);
		free(ge);
		return NULL;
	}

	LIST_INSERT_HEAD(&cl->lg_geom, ge, lg_geom);

	return ge;
}

static struct gprovider *
fakegeom_add_gprovider(struct gmesh *gmp, struct ggeom *ge, const char *name,
    off_t mediasize, u_int sectorsize, off_t stripeoffset, off_t stripesize)
{
	struct gprovider *pr;
	int error;

	pr = malloc(sizeof(*pr));
	if (pr == NULL)
		return NULL;
	pr->lg_id = NULL;
	pr->lg_name = strdup(name);
	if (pr->lg_name == NULL) {
		free(pr);
		return NULL;
	}
	LIST_INIT(&pr->lg_consumers);
	pr->lg_mode = strdup("r0w0e0");	/* XXX */
	if (pr->lg_mode == NULL) {
		free(pr->lg_name);
		free(pr);
		return NULL;
	}
	pr->lg_mediasize = mediasize;
	pr->lg_sectorsize = sectorsize;
	pr->lg_stripeoffset = stripeoffset;
	pr->lg_stripesize = stripesize;
	LIST_INIT(&pr->lg_config);

	error = fakegeom_add_ident(gmp, ISPROVIDER, pr);
	if (error != 0) {
		free(pr->lg_mode);
		free(pr->lg_name);
		free(pr);
		return NULL;
	}

	LIST_INSERT_HEAD(&ge->lg_provider, pr, lg_provider);

	return pr;
}

static struct gconsumer *
fakegeom_add_gconsumer(struct gmesh *gmp, struct ggeom *ge)
{
	struct gconsumer *co;
	struct gprovider *pr = LIST_FIRST(&ge->lg_provider); /* XXX */
	int error;

	co = malloc(sizeof(*co));
	if (co == NULL)
		return NULL;
	co->lg_id = NULL;
	co->lg_provider = pr;
	co->lg_mode = strdup("r0w0e0");	/* XXX */
	if (co->lg_mode == NULL) {
		free(co);
		return NULL;
	}
	LIST_INIT(&co->lg_config);

	error = fakegeom_add_ident(gmp, ISCONSUMER, co);
	if (error != 0) {
		free(co->lg_mode);
		free(co);
		return NULL;
	}

	LIST_INSERT_HEAD(&ge->lg_consumer, co, lg_consumer);
	LIST_INSERT_HEAD(&pr->lg_consumers, co, lg_consumers); /* XXX need? */

	return co;
}

static const char *
fekegeom_get_part_scheme(gpt_t gpt)
{
	map_t m;

	for (m = map_first(gpt); m != NULL; m = m->map_next) {
		switch (m->map_type) {
		case MAP_TYPE_PRI_GPT_HDR:
		case MAP_TYPE_SEC_GPT_HDR:
		case MAP_TYPE_PRI_GPT_TBL:
		case MAP_TYPE_SEC_GPT_TBL:
		case MAP_TYPE_GPT_PART:
			return "GPT";
		case MAP_TYPE_MBR_PART:
			return "MBR";
		}
	}
	return NULL;
}

static int
fakegeom_add_part_geom_config(struct gmesh *gmp, struct ggeom *ge, gpt_t gpt)
{
	struct gconf *head = &ge->lg_config;
	struct gconfig *cf;
	struct gpt_hdr *hdr;
	const char *scheme;

	scheme = fekegeom_get_part_scheme(gpt);
	if (scheme == NULL)
		return EINVAL;

	hdr = gpt_hdr(gpt);

	cf = fakegeom_add_gconfig(head, "scheme", scheme);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "entries", hdr->hdr_entries);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "first", hdr->hdr_lba_start);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "last", hdr->hdr_lba_end);
	if (cf == NULL)
		return ENOMEM;
	/* fwsectors */
	/* fwheads */
	cf = fakegeom_add_gconfig(head, "state", "OK");
	if (cf == NULL)
		return ENOMEM;
	/* modified */

	return 0;
}

static int
fakegeom_add_part_provider_config(struct gmesh *gmp, struct gprovider *pr,
    gpt_t gpt, map_t m, const struct fakegeom_diskinfo *di)
{
	char efimedia[256];
	struct gconf *head = &pr->lg_config;
	struct gconfig *cf;
	const char *scheme;
	uintmax_t startsec, endsec;

	scheme = fekegeom_get_part_scheme(gpt);
	if (scheme == NULL)
		return EINVAL;

	startsec = di->dkw.dkw_offset / di->geo.dg_secsize;
	endsec = di->dkw.dkw_offset + di->dkw.dkw_size + 1;
	endsec /= di->geo.dg_secsize;

	cf = fakegeom_add_gconfig_uint(head, "start", startsec);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "end", endsec);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "index", m->map_index);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig(head, "type", di->dkw.dkw_ptype);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "offset", di->dkw.dkw_offset);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig_uint(head, "length", di->dkw.dkw_size);
	if (cf == NULL)
		return ENOMEM;
	cf = fakegeom_add_gconfig(head, "label", di->dkw.dkw_ptype);
	if (cf == NULL)
		return ENOMEM;
	if (strcmp(scheme, "GPT") == 0) {
		struct gpt_ent *ent = m->map_data;
		uint8_t utfbuf[__arraycount(ent->ent_name) * 3 + 1];
		char uuidbuf[128];

		utf16_to_utf8(ent->ent_name, __arraycount(ent->ent_name),
		    utfbuf, __arraycount(utfbuf));
		cf = fakegeom_add_gconfig(head, "label", utfbuf);
		if (cf == NULL)
			return ENOMEM;
		if (ent->ent_attr & GPT_ENT_ATTR_BOOTME) {
			cf = fakegeom_add_gconfig(head, "attrib", "bootme");
			if (cf == NULL)
				return ENOMEM;
		}
		if (ent->ent_attr & GPT_ENT_ATTR_BOOTONCE) {
			cf = fakegeom_add_gconfig(head, "attrib", "bootonce");
			if (cf == NULL)
				return ENOMEM;
		}
		if (ent->ent_attr & GPT_ENT_ATTR_BOOTFAILED) {
			cf = fakegeom_add_gconfig(head, "attrib", "bootfailed");
			if (cf == NULL)
				return ENOMEM;
		}
		gpt_uuid_snprintf(uuidbuf, sizeof(uuidbuf), "%d",
		    ent->ent_type);
		cf = fakegeom_add_gconfig(head, "rawtype", uuidbuf);
		if (cf == NULL)
			return ENOMEM;
		gpt_uuid_snprintf(uuidbuf, sizeof(uuidbuf), "%d",
		    ent->ent_guid);
		cf = fakegeom_add_gconfig(head, "rawuuid", uuidbuf);
		if (cf == NULL)
			return ENOMEM;
		snprintf(efimedia, sizeof(efimedia),
		    "HD(%u,GPT,%s,%#" PRIxMAX ",%#" PRIxMAX ")",
		    m->map_index, uuidbuf, startsec, endsec);
		cf = fakegeom_add_gconfig(head, "efimedia", efimedia);
		if (cf == NULL)
			return ENOMEM;
	} else if (strcmp(scheme, "MBR") == 0) {
		map_t mbr_m = m->map_data;
		struct mbr *mbr = mbr_m->map_data;
		struct mbr_part *part = &mbr->mbr_part[m->map_index];

		cf = fakegeom_add_gconfig_uint(head, "rawtype", part->part_typ);
		if (cf == NULL)
			return ENOMEM;
		if (part->part_flag & MBR_PFLAG_ACTIVE) {
			cf = fakegeom_add_gconfig(head, "attrib", "active");
			if (cf == NULL)
				return ENOMEM;
		}
		snprintf(efimedia, sizeof(efimedia),
		    "HD(%u,MBR,%#08x,%#" PRIxMAX ",%#" PRIxMAX ")",
		    m->map_index, le32dec(&mbr->mbr_code[MBR_DSN_OFFSET]),
		    startsec, endsec);
		cf = fakegeom_add_gconfig(head, "efimedia", efimedia);
		if (cf == NULL)
			return ENOMEM;
	}

	return 0;
}

static struct gprovider *
fakegeom_add_part_provider(struct gmesh *gmp, struct ggeom *ge, gpt_t gpt,
    map_t m, const struct fakegeom_diskinfo *di)
{
	struct gprovider *pr;
	int error;

	pr = malloc(sizeof(*pr));
	if (pr == NULL)
		return NULL;
	pr->lg_id = NULL;
	pr->lg_name = strdup(di->dkw.dkw_devname);
	if (pr->lg_name == NULL) {
		free(pr);
		return NULL;
	}
	LIST_INIT(&pr->lg_consumers);
	pr->lg_mode = strdup("r0w0e0");	/* XXX */
	if (pr->lg_mode == NULL) {
		free(pr->lg_name);
		free(pr);
		return NULL;
	}
	pr->lg_mediasize = di->geo.dg_secsize * di->geo.dg_secperunit;
	pr->lg_sectorsize = di->geo.dg_secsize;
	pr->lg_stripeoffset = 0; /* XXX */
	pr->lg_stripesize = 0;
	LIST_INIT(&pr->lg_config);

	error = fakegeom_add_part_provider_config(gmp, pr, gpt, m, di);
	if (error) {
		errno = error;
		return NULL;
	}

	error = fakegeom_add_ident(gmp, ISPROVIDER, pr);
	if (error != 0) {
		free(pr->lg_mode);
		free(pr->lg_name);
		free(pr);
		return NULL;
	}

	LIST_INSERT_HEAD(&ge->lg_provider, pr, lg_provider);

	return pr;
}

static int
fakegeom_make(struct gmesh *gmp)
{
	static const char *logical_disks[] = {
		"ccd", "cgd", "dk", "raid"
	};
	static const int nodes[] = { CTL_HW, HW_DISKNAMES };
	const struct fakegeom_diskinfo *di;
	struct gclass *diskcl, *labelcl, *partcl, *devcl;
	struct ggeom *ge, *ge0;
	struct gprovider *pr;
	struct gconsumer *co;
	gpt_t gpt;
	map_t m;
	char *disknames, *p, *ep;
	size_t len;
	off_t mediasz;
	u_int secsz;
	int i, error;

	LIST_INIT(&gmp->lg_class);
	gmp->lg_ident = NULL;
	gmp->_lg_nident = 0;
	gmp->_lg_aident = 0;

	disknames = asysctl(nodes, __arraycount(nodes), &len);
	if (disknames == NULL)
		return errno;

	gmp->_lg_aident = 64;
	error = reallocarr(&gmp->lg_ident, gmp->_lg_aident,
	    sizeof(*gmp->lg_ident));
	if (error != 0)
		goto out;

	diskcl = fakegeom_add_gclass(gmp, G_DISK);
	if (diskcl == NULL)
		goto out;
	partcl = fakegeom_add_gclass(gmp, G_PART);
	if (partcl == NULL)
		goto out;
	labelcl = fakegeom_add_gclass(gmp, G_LABEL);
	if (labelcl == NULL)
		goto out;
	devcl = fakegeom_add_gclass(gmp, G_DEV);
	if (devcl == NULL)
		goto out;

	/* DISK */
	for (p = strtok_r(disknames, " ", &ep);
	    p != NULL;
	    p = strtok_r(NULL, " ", &ep)) {

		for (i = 0; i < (int)__arraycount(logical_disks); i++) {
			len = strlen(logical_disks[i]);
			if (strncmp(p, logical_disks[i], len) == 0)
				continue;
		}

		error = getdisksize(p, &secsz, &mediasz);
		if (error == -1) {
			error = errno;
			goto out;
		}

		ge = fakegeom_add_ggeom(gmp, diskcl, p, 1);
		if (ge == NULL)
			goto out;

		pr = fakegeom_add_gprovider(gmp, ge, p, mediasz, secsz, 0, 0);
		if (pr == NULL)
			goto out;
	}

	/* PART */
	LIST_FOREACH(ge0, &diskcl->lg_geom, lg_geom) {
		ge = fakegeom_add_ggeom(gmp, partcl, ge0->lg_name, 2);
		if (ge == NULL)
			goto out;

		co = fakegeom_add_gconsumer(gmp, ge);
		if (co == NULL)
			goto out;

		gpt = gpt_open(ge->lg_name, GPT_QUIET | GPT_READONLY,
		    0, 0, 0, 0);
		if (gpt == NULL)
			continue;
		gpt_close(gpt);

		error = fakegeom_add_part_geom_config(gmp, ge, gpt);
		if (error != 0)
			goto out;

		/* dk */
		for (p = strtok_r(disknames, " ", &ep);
		    p != NULL;
		    p = strtok_r(NULL, " ", &ep)) {

			if (strncmp(p, "dk", 2) != 0)
				continue;

			di = fakegeom_get_diskinfo(p);
			if (di == NULL)
				continue;

			if (strcmp(ge->lg_name, di->dkw.dkw_parent) != 0)
				continue;

			for (m = map_first(gpt); m != NULL; m = m->map_next) {
				if (di->dkw.dkw_offset == m->map_start &&
				    m->map_size >= 0 &&
				    di->dkw.dkw_size == (uint64_t)m->map_size) {
					pr = fakegeom_add_part_provider(gmp,
					    ge, gpt, m, di);
					if (pr == NULL)
						goto out;
				}
			}
		}
	}

	/* LABEL */

	/* DEV */

out:
	if (error != 0)
		fakegeom_free(gmp);
	free(disknames);
	return error;
}
