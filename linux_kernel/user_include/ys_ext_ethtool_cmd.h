/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _YS_EXT_ETHTOOL_CMD_H
#define _YS_EXT_ETHTOOL_CMD_H

/* CMDs currently supported */
#define YS_EXT_ETHTOOL_GSET		0x00000001 /* DEPRECATED, Get settings.
						    * Please use ETHTOOL_GLINKSETTINGS
						    */
#define YS_EXT_ETHTOOL_SSET		0x00000002 /* DEPRECATED, Set settings.
						    * Please use ETHTOOL_SLINKSETTINGS
						    */
#define YS_EXT_ETHTOOL_GDRVINFO		0x00000003 /* Get driver info. */
#define YS_EXT_ETHTOOL_GREGS		0x00000004 /* Get NIC registers. */
#define YS_EXT_ETHTOOL_GWOL		0x00000005 /* Get wake-on-lan options. */
#define YS_EXT_ETHTOOL_SWOL		0x00000006 /* Set wake-on-lan options. */
#define YS_EXT_ETHTOOL_GMSGLVL		0x00000007 /* Get driver message level */
#define YS_EXT_ETHTOOL_SMSGLVL		0x00000008 /* Set driver msg level. */
#define YS_EXT_ETHTOOL_NWAY_RST		0x00000009 /* Restart autonegotiation. */
/* Get link status for host, i.e. whether the interface *and* the
 * physical port (if there is one) are up (ethtool_value).
 */
#define YS_EXT_ETHTOOL_GLINK		0x0000000a
#define YS_EXT_ETHTOOL_GEEPROM		0x0000000b /* Get EEPROM data */
#define YS_EXT_ETHTOOL_SEEPROM		0x0000000c /* Set EEPROM data. */
#define YS_EXT_ETHTOOL_GCOALESCE	0x0000000e /* Get coalesce config */
#define YS_EXT_ETHTOOL_SCOALESCE	0x0000000f /* Set coalesce config. */
#define YS_EXT_ETHTOOL_GRINGPARAM	0x00000010 /* Get ring parameters */
#define YS_EXT_ETHTOOL_SRINGPARAM	0x00000011 /* Set ring parameters. */
#define YS_EXT_ETHTOOL_GPAUSEPARAM	0x00000012 /* Get pause parameters */
#define YS_EXT_ETHTOOL_SPAUSEPARAM	0x00000013 /* Set pause parameters. */
#define YS_EXT_ETHTOOL_GRXCSUM		0x00000014 /* Get RX hw csum enable (ethtool_value) */
#define YS_EXT_ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
#define YS_EXT_ETHTOOL_GTXCSUM		0x00000016 /* Get TX hw csum enable (ethtool_value) */
#define YS_EXT_ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
#define YS_EXT_ETHTOOL_GSG		0x00000018 /* Get scatter-gather enable (ethtool_value) */
#define YS_EXT_ETHTOOL_SSG		0x00000019 /* Set scatter-gather enable (ethtool_value). */
#define YS_EXT_ETHTOOL_TEST		0x0000001a /* execute NIC self-test. */
#define YS_EXT_ETHTOOL_GSTRINGS		0x0000001b /* get specified string set */
#define YS_EXT_ETHTOOL_PHYS_ID		0x0000001c /* identify the NIC */
#define YS_EXT_ETHTOOL_GSTATS		0x0000001d /* get NIC-specific statistics */
#define YS_EXT_ETHTOOL_GTSO		0x0000001e /* Get TSO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_STSO		0x0000001f /* Set TSO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_GPERMADDR	0x00000020 /* Get permanent hardware address */
#define YS_EXT_ETHTOOL_GUFO		0x00000021 /* Get UFO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_SUFO		0x00000022 /* Set UFO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_GGSO		0x00000023 /* Get GSO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_SGSO		0x00000024 /* Set GSO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_GFLAGS		0x00000025 /* Get flags bitmap(ethtool_value) */
#define YS_EXT_ETHTOOL_SFLAGS		0x00000026 /* Set flags bitmap(ethtool_value) */
#define YS_EXT_ETHTOOL_GPFLAGS		0x00000027 /* Get driver-private flags bitmap */
#define YS_EXT_ETHTOOL_SPFLAGS		0x00000028 /* Set driver-private flags bitmap */

#define YS_EXT_ETHTOOL_GRXFH		0x00000029 /* Get RX flow hash configuration */
#define YS_EXT_ETHTOOL_SRXFH		0x0000002a /* Set RX flow hash configuration */
#define YS_EXT_ETHTOOL_GGRO		0x0000002b /* Get GRO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_SGRO		0x0000002c /* Set GRO enable (ethtool_value) */
#define YS_EXT_ETHTOOL_GRXRINGS		0x0000002d /* Get RX rings available for LB */
#define YS_EXT_ETHTOOL_GRXCLSRLCNT	0x0000002e /* Get RX class rule count */
#define YS_EXT_ETHTOOL_GRXCLSRULE	0x0000002f /* Get RX classification rule */
#define YS_EXT_ETHTOOL_GRXCLSRLALL	0x00000030 /* Get all RX classification rule */
#define YS_EXT_ETHTOOL_SRXCLSRLDEL	0x00000031 /* Delete RX classification rule */
#define YS_EXT_ETHTOOL_SRXCLSRLINS	0x00000032 /* Insert RX classification rule */
#define YS_EXT_ETHTOOL_FLASHDEV		0x00000033 /* Flash firmware to device */
#define YS_EXT_ETHTOOL_RESET		0x00000034 /* Reset hardware */
#define YS_EXT_ETHTOOL_SRXNTUPLE	0x00000035 /* Add an n-tuple filter to device */
#define YS_EXT_ETHTOOL_GRXNTUPLE	0x00000036 /* deprecated */
#define YS_EXT_ETHTOOL_GSSET_INFO	0x00000037 /* Get string set info */
#define YS_EXT_ETHTOOL_GRXFHINDIR	0x00000038 /* Get RX flow hash indir'n table */
#define YS_EXT_ETHTOOL_SRXFHINDIR	0x00000039 /* Set RX flow hash indir'n table */

#define YS_EXT_ETHTOOL_GFEATURES	0x0000003a /* Get device offload settings */
#define YS_EXT_ETHTOOL_SFEATURES	0x0000003b /* Change device offload settings */
#define YS_EXT_ETHTOOL_GCHANNELS	0x0000003c /* Get no of channels */
#define YS_EXT_ETHTOOL_SCHANNELS	0x0000003d /* Set no of channels */
#define YS_EXT_ETHTOOL_SET_DUMP		0x0000003e /* Set dump settings */
#define YS_EXT_ETHTOOL_GET_DUMP_FLAG	0x0000003f /* Get dump settings */
#define YS_EXT_ETHTOOL_GET_DUMP_DATA	0x00000040 /* Get dump data */
#define YS_EXT_ETHTOOL_GET_TS_INFO	0x00000041 /* Get time stamping and PHC info */
#define YS_EXT_ETHTOOL_GMODULEINFO	0x00000042 /* Get plug-in module information */
#define YS_EXT_ETHTOOL_GMODULEEEPROM	0x00000043 /* Get plug-in module eeprom */
#define YS_EXT_ETHTOOL_GEEE		0x00000044 /* Get EEE settings */
#define YS_EXT_ETHTOOL_SEEE		0x00000045 /* Set EEE settings */

#define YS_EXT_ETHTOOL_GRSSH		0x00000046 /* Get RX flow hash configuration */
#define YS_EXT_ETHTOOL_SRSSH		0x00000047 /* Set RX flow hash configuration */
#define YS_EXT_ETHTOOL_GTUNABLE		0x00000048 /* Get tunable configuration */
#define YS_EXT_ETHTOOL_STUNABLE		0x00000049 /* Set tunable configuration */
#define YS_EXT_ETHTOOL_GPHYSTATS	0x0000004a /* get PHY-specific statistics */

#define YS_EXT_ETHTOOL_PERQUEUE		0x0000004b /* Set per queue options */

#define YS_EXT_ETHTOOL_GLINKSETTINGS	0x0000004c /* Get ethtool_link_settings */
#define YS_EXT_ETHTOOL_SLINKSETTINGS	0x0000004d /* Set ethtool_link_settings */
#define YS_EXT_ETHTOOL_PHY_GTUNABLE	0x0000004e /* Get PHY tunable configuration */
#define YS_EXT_ETHTOOL_PHY_STUNABLE	0x0000004f /* Set PHY tunable configuration */
#define YS_EXT_ETHTOOL_GFECPARAM	0x00000050 /* Get FEC settings */
#define YS_EXT_ETHTOOL_SFECPARAM	0x00000051 /* Set FEC settings */

#define YS_EXT_ETHTOOL_GREGS_LEN	0x00000060 /* Get NIC registers length. */
#define YS_EXT_ETHTOOL_GEEPROM_LEN	0x00000061 /* Get EEPROM data length */
#define YS_EXT_ETHTOOL_GRXFHINDIR_SIZE	0x00000062 /* Get RX flow hash indir'n table size*/
#define YS_EXT_ETHTOOL_GRXFHKEY_SIZE	0x00000063 /* Get RX flow hash key size */
#define YS_EXT_ETHTOOL_GSSET_COUNT	0x00000064 /* Get string set count */
#endif
