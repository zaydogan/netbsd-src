# $NetBSD$

USE_FORT?=	yes	# data driven bugs?

S=		${.CURDIR}/../..
GNUEFIDIR=	${S}/sys/external/bsd/gnu-efi/dist

.include <bsd.own.mk>

.if "${MACHINE_ARCH}" == "i386"
GNUEFIARCH=ia32
.else
GNUEFIARCH=${MACHINE_ARCH}
.endif

WARNS?=		6

LIB=		efivar

CPPFLAGS+=	-I${.CURDIR}
CPPFLAGS+=	-I${GNUEFIDIR}/inc
CPPFLAGS+=	-I${GNUEFIDIR}/inc/${GNUEFIARCH}

SRCS=		efivar.c
SRCS+=		efichar.c
SRCS+=		efivar-dp-format.c
SRCS+=		efivar-dp-parse.c
#SRCS+=		efivar-dp-xlate.c
SRCS+=		uefi-dputil.c
SRCS+=		uefi-guid.c

MAN=		efivar.3
MLINKS+=	efivar.3 efi_set_variables_supported.3
MLINKS+=	efivar.3 efi_del_variable.3
MLINKS+=	efivar.3 efi_get_variable.3
MLINKS+=	efivar.3 efi_get_variable_attributes.3
MLINKS+=	efivar.3 efi_get_variable_size.3
MLINKS+=	efivar.3 efi_append_variable.3
MLINKS+=	efivar.3 efi_set_variable.3
MLINKS+=	efivar.3 efi_get_next_variable_name.3
MLINKS+=	efivar.3 efi_str_to_guid.3
MLINKS+=	efivar.3 efi_guid_to_str.3
MLINKS+=	efivar.3 efi_name_to_guid.3
MLINKS+=	efivar.3 efi_guid_to_name.3
MLINKS+=	efivar.3 efi_guid_to_symbol.3
MLINKS+=	efivar.3 libefivar.3

INCS=		efivar.h efivar-dp.h
INCSDIR=	/usr/include

.include <bsd.lib.mk>

CFLAGS+=	-fno-strict-aliasing
CFLAGS+=	-Wno-strict-prototypes
CFLAGS+=	-Wno-sign-conversion
CFLAGS+=	-Wno-pointer-sign
CFLAGS+=	-Wno-unused-but-set-variable
