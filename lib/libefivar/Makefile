# $NetBSD$

.include <bsd.own.mk>

WARNS?=	5
LIB=	efivar
CPPFLAGS+=-I${.CURDIR}
SRCS=	efivar.c libefivar.c

MAN=	efivar.3

MLINKS+=efivar.3 efi_set_variables_supported.3
MLINKS+=efivar.3 efi_del_variable.3
MLINKS+=efivar.3 efi_get_variable.3
MLINKS+=efivar.3 efi_get_variable_attributes.3
MLINKS+=efivar.3 efi_get_variable_size.3
MLINKS+=efivar.3 efi_append_variable.3
MLINKS+=efivar.3 efi_set_variable.3
MLINKS+=efivar.3 efi_get_next_variable_name.3
MLINKS+=efivar.3 efi_str_to_guid.3
MLINKS+=efivar.3 efi_guid_to_str.3
MLINKS+=efivar.3 efi_name_to_guid.3
MLINKS+=efivar.3 efi_guid_to_name.3
MLINKS+=efivar.3 efi_guid_to_symbol.3
MLINKS+=efivar.3 libefivar.3

INCS=	efivar.h
INCSDIR=/usr/include

.include <bsd.lib.mk>
