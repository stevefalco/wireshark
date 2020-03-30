// packet-pidp11.c
// Routines for pidp11 dissection
// Copyright 2020, Steven A. Falco <stevenfalco@gmail.com>
//
// Wireshark - Network traffic analyzer
// By Gerald Combs <gerald@wireshark.org>
// Copyright 1998 Gerald Combs
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include <config.h>

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/dissectors/packet-udp.h>

#define MIN_LEN		28

#define BUF_LEN		128

#define ENABLE_DEBUG

#define RPC_BLINKENLIGHT_API_GETINFO			1
#define RPC_BLINKENLIGHT_API_GETPANELINFO		2
#define RPC_BLINKENLIGHT_API_GETCONTROLINFO		3
#define RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES	4
#define RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES	5
#define RPC_PARAM_GET					100
#define RPC_PARAM_SET					101
#define RPC_TEST_DATA_TO_SERVER				1000
#define RPC_TEST_DATA_FROM_SERVER			1001

#define PRIMARY_MIN	RPC_BLINKENLIGHT_API_GETINFO
#define PRIMARY_MAX	RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES
#define PRIMARY(a)	(((a) >= PRIMARY_MIN) && ((a) <= PRIMARY_MAX))

#define SECONDARY_MIN	RPC_PARAM_GET
#define SECONDARY_MAX	RPC_PARAM_SET
#define SECONDARY(a)	(((a) >= SECONDARY_MIN) && ((a) <= SECONDARY_MAX))

#define TERTIARY_MIN	RPC_TEST_DATA_TO_SERVER
#define TERTIARY_MAX	RPC_TEST_DATA_FROM_SERVER
#define TERTIARY(a)	(((a) >= TERTIARY_MIN) && ((a) <= TERTIARY_MAX))

static const value_string blinken_function[] = {
	{ RPC_BLINKENLIGHT_API_GETINFO,			"RPC_BLINKENLIGHT_API_GETINFO"},
	{ RPC_BLINKENLIGHT_API_GETPANELINFO,		"RPC_BLINKENLIGHT_API_GETPANELINFO"},
	{ RPC_BLINKENLIGHT_API_GETCONTROLINFO,		"RPC_BLINKENLIGHT_API_GETCONTROLINFO"},
	{ RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES,	"RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES"},
	{ RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES,	"RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES"},
	{ RPC_PARAM_GET,				"RPC_PARAM_GET"},
	{ RPC_PARAM_SET,				"RPC_PARAM_SET"},
	{ RPC_TEST_DATA_TO_SERVER,			"RPC_TEST_DATA_TO_SERVER"},
	{ RPC_TEST_DATA_FROM_SERVER,			"RPC_TEST_DATA_FROM_SERVER"},
	{ 0,	NULL }
};

static const value_string RPC_direction[] = {
	{ 0, "Request from SIMH to Panel"},
	{ 1, "Reply from Panel to SIMH"},
	{ 0, NULL }
};

static const value_string input_output[] = {
	{ 0, "Output"},
	{ 1, "Input"},
	{ 0, NULL }
};

static const value_string component_type[] = {
	{ 1, "Switch"},
	{ 2, "LED"},
	{ 0, NULL }
};

static const value_string component_radix[] = {
	{ 1, "Binary"},
	{ 8, "Octal"},
	{ 10, "Decimal"},
	{ 16, "Hexadecimal"},
	{ 0, NULL }
};

#ifdef ENABLE_DEBUG
#define DEBUG(fmt, ... ) logit(fmt, ##__VA_ARGS__ )

static void logit(const char *format, ...)
{
	va_list		ap;
	static FILE	*logfp = 0;

	if(logfp == 0) {
		logfp = fopen("/home/sfalco/log.wire", "w");
		fprintf(logfp, "opened log\n");
		fflush(logfp);
	}

	if(logfp) {
		va_start(ap, format);
		vfprintf(logfp, format, ap);
		va_end(ap);
		fprintf(logfp, "\n");
		fflush(logfp);
	}
}
#else
#define DEBUG(fmt, ...)
#endif

/* Prototypes */
void proto_reg_handoff_pidp11(void);
void proto_register_pidp11(void);

// Initialize the protocol.
static int		proto_pidp11 = -1;

// Initialize registered fields.
static int		hf_pidp11_sequence_number = -1;
static int		hf_pidp11_direction = -1;
static int		hf_pidp11_rpc_version = -1;
static int		hf_pidp11_program_number = -1;
static int		hf_pidp11_blinken_version = -1;
static int		hf_pidp11_blinken_function = -1;
static int		hf_pidp11_error_code = -1;
static int		hf_pidp11_getinfo_info = -1;
static int		hf_pidp11_getpanelinfo_name = -1;
static int		hf_pidp11_getpanelinfo_in_count = -1;
static int		hf_pidp11_getpanelinfo_out_count = -1;
static int		hf_pidp11_getpanelinfo_in_bytes = -1;
static int		hf_pidp11_getpanelinfo_out_bytes = -1;
static int		hf_pidp11_getcontrolinfo_index = -1;
static int		hf_pidp11_getcontrolinfo_name = -1;
static int		hf_pidp11_getcontrolinfo_input = -1;
static int		hf_pidp11_getcontrolinfo_type = -1;
static int		hf_pidp11_getcontrolinfo_radix = -1;
static int		hf_pidp11_getcontrolinfo_bits = -1;
static int		hf_pidp11_getcontrolinfo_bytes = -1;

// Values of the fields.
static uint32_t		pidp11_sequence_number = -1;
static int		pidp11_direction = -1;
static int		pidp11_rpc_version = -1;
static int		pidp11_program_number = -1;
static int		pidp11_blinken_version = -1;
static int		pidp11_blinken_function = -1;
static int		pidp11_control_index = -1;

struct pidp11_request_key {
	guint32		conversation;
	guint32		sequence_number;
};

struct pidp11_request_val {
	guint		req_num;
	guint		rep_num;

	uint32_t	pidp11_sequence_number;
	int		pidp11_direction;
	int		pidp11_rpc_version;
	int		pidp11_program_number;
	int		pidp11_blinken_version;
	int		pidp11_blinken_function;

	int		pidp11_control_index;
};

static wmem_map_t *pidp11_request_hash = NULL;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define pidp11_UDP_PORT 0
static guint udp_port_pref = pidp11_UDP_PORT;

// Initialize the subtree pointer(s).
static gint ett_top_level = -1;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define pidp11_MIN_LENGTH 8

static char *low_funcs[] = {
	"Get Info",
	"Get Panel",
	"Get Control Info",
	"Set Control Value",
	"Get Control Value",
};

static char *mid_funcs[] = {
	"Get RPC Param",
	"Set RPC Param",
};

static char *high_funcs[] = {
	"Test To Server",
	"Test From Server",
};

static gint
pidp11_equal(gconstpointer v, gconstpointer w)
{
	const struct pidp11_request_key *v1 = (const struct pidp11_request_key *)v;
	const struct pidp11_request_key *v2 = (const struct pidp11_request_key *)w;

	DEBUG("pidp11_equal %08x vs %08x, %08x vs %08x", v1->conversation, v2->conversation, v1->sequence_number, v2->sequence_number);
	if((v1->conversation == v2->conversation) && (v1->sequence_number == v2->sequence_number)) {
		DEBUG("pidp11_equal yes");
		return 1;
	}

	DEBUG("pidp11_equal no");
	return 0;
}

static guint
pidp11_hash(gconstpointer v)
{
	const struct pidp11_request_key *key = (const struct pidp11_request_key *)v;
	guint val;

	val = key->conversation + key->sequence_number;
	DEBUG("pidp11_hash %08x", val);

	return val;
}

/* Code to actually dissect the packets */
static int
dissect_pidp11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *pidp11_tree;

	conversation_t *conversation;
	struct pidp11_request_key request_key;
	struct pidp11_request_key *new_request_key;
	struct pidp11_request_val *request_val = NULL;

	guint		offset	= 0;
	int		len	= 0;
	char		buf[BUF_LEN];

	DEBUG("dissect_pidp11");

	// Check that the packet is long enough for it to belong to us.  The
	// shortest has MIN_LEN bytes of data after the UDP header.
	if(tvb_reported_length(tvb) < MIN_LEN) {
		return 0;
	}

	// Check that there's enough data present to run the heuristics.
	if(tvb_captured_length(tvb) < MIN_LEN) {
		return 0;
	}

	// Look up the values in the common packet fields.
	pidp11_sequence_number		= tvb_get_ntohl(tvb, 0x00);
	pidp11_direction		= tvb_get_ntohl(tvb, 0x04);
	pidp11_rpc_version		= tvb_get_ntohl(tvb, 0x08);
	pidp11_program_number		= tvb_get_ntohl(tvb, 0x0c);
	pidp11_blinken_version		= tvb_get_ntohl(tvb, 0x10);
	pidp11_blinken_function		= tvb_get_ntohl(tvb, 0x14);

	if(pidp11_direction == 0) {
		// To server.
		if(pidp11_rpc_version != 2) {
			return 0;
		}

		if(pidp11_program_number != 99) {
			return 0;
		}

		if(pidp11_blinken_version != 1) {
			return 0;
		}

		if(PRIMARY(pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Client (%s)", low_funcs[pidp11_blinken_function - PRIMARY_MIN]);
		} else if(SECONDARY(pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Client (%s)", mid_funcs[pidp11_blinken_function - SECONDARY_MIN]);
		} else if(TERTIARY(pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Client (%s)", high_funcs[pidp11_blinken_function - TERTIARY_MIN]);
		} else {
			return 0;
		}

		if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
			pidp11_control_index = tvb_get_ntohl(tvb, 0x2c);
		}
	} else if(pidp11_direction == 1) {
		// To client.
		if(pidp11_rpc_version != 0) {
			return 0;
		}

		if(pidp11_program_number != 0) {
			return 0;
		}

		if(pidp11_blinken_version != 0) {
			return 0;
		}

		if(pidp11_blinken_function != 0) {
			return 0;
		}
	} else {
		return 0;
	}

	conversation = find_or_create_conversation(pinfo);

	request_key.conversation = conversation->conv_index;
	request_key.sequence_number = pidp11_sequence_number;

	request_val = (struct pidp11_request_val *) wmem_map_lookup(pidp11_request_hash, &request_key);

	// Only allocate a new hash element when it's a call from SIMH to the panel.
	if(!pinfo->fd->visited) {
		DEBUG("not visited yet");
		if(!request_val && (pidp11_direction == 0)) {
			DEBUG("no val and dir == to server, inserting request %d", pinfo->num);
			new_request_key = wmem_new(wmem_file_scope(), struct pidp11_request_key);
			*new_request_key = request_key;

			request_val = wmem_new(wmem_file_scope(), struct pidp11_request_val);
			request_val->req_num			= pinfo->num;
			request_val->rep_num			= 0;
			request_val->pidp11_sequence_number	= pidp11_sequence_number;
			request_val->pidp11_direction		= pidp11_direction;
			request_val->pidp11_rpc_version		= pidp11_rpc_version;
			request_val->pidp11_program_number	= pidp11_program_number;
			request_val->pidp11_blinken_version	= pidp11_blinken_version;
			request_val->pidp11_blinken_function	= pidp11_blinken_function;

			request_val->pidp11_control_index	= 0;
			if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
				request_val->pidp11_control_index = pidp11_control_index;
			}

			wmem_map_insert(pidp11_request_hash, new_request_key, request_val);
		}

		if(request_val && (pidp11_direction == 1)) {
			DEBUG("val exists and dir == to client, inserting reply %d", pinfo->num);
			request_val->rep_num = pinfo->num;
		}
	}

	if(request_val && (pidp11_direction == 1)) {
		// Server (Panel)
		DEBUG("val exists, our seq=0x%08x, hashed seq=0x%08x", pidp11_sequence_number, request_val->pidp11_sequence_number);
		if(PRIMARY(request_val->pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Server (%s)", low_funcs[request_val->pidp11_blinken_function - PRIMARY_MIN]);
		} else if(SECONDARY(request_val->pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Server (%s)", mid_funcs[request_val->pidp11_blinken_function - SECONDARY_MIN]);
		} else if(TERTIARY(request_val->pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Server (%s)", high_funcs[request_val->pidp11_blinken_function - TERTIARY_MIN]);
		} else {
			g_snprintf(buf, BUF_LEN, "Server (not matched)");
		}

		DEBUG("dissect_pidp11 adding tree");
		ti = proto_tree_add_item(tree, proto_pidp11, tvb, 0, -1, ENC_NA);
		DEBUG("dissect_pidp11 added tree");

		pidp11_tree = proto_item_add_subtree(ti, ett_top_level);

		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);

		offset += len;
		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);

		proto_tree_add_uint(pidp11_tree, hf_pidp11_blinken_function, tvb, 0, 0, request_val->pidp11_blinken_function);

		if(PRIMARY(request_val->pidp11_blinken_function)) {
			offset = 0x18;
			len = 4;
			proto_tree_add_uint(pidp11_tree, hf_pidp11_error_code, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			if(request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETINFO) {
				// It would be better to honor the \n chars here.  len is equal to the total length of the
				// string, including the 4-byte size field preceding the string characters.
				//
				// Note that strings are padded with nulls to the next 4-byte boundary.
				len = 4 + (((tvb_get_ntohl(tvb, offset) + 3) / 4) * 4);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getinfo_info, tvb, offset, 4, ENC_UTF_8 | ENC_BIG_ENDIAN);
			} else if(request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANELINFO) {
				len = 4 + (((tvb_get_ntohl(tvb, offset) + 3) / 4) * 4);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_name, tvb, offset, 4, ENC_UTF_8 | ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_in_count, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_out_count, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_in_bytes, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_out_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
			} else if(request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
				// We have to add each control to a list, so we can find it again, when we interpret the
				// control values.  If the capture doesn't include these messages, then we won't be able
				// to put names to the control values.  We might pre-populate the list with the expected
				// names and show them with ? to indicate uncertainty...
				proto_tree_add_uint(pidp11_tree, hf_pidp11_getcontrolinfo_index, tvb, 0, 0, request_val->pidp11_control_index);

				len = 4 + (((tvb_get_ntohl(tvb, offset) + 3) / 4) * 4);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_name, tvb, offset, 4, ENC_UTF_8 | ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_input, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_type, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_radix, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_bits, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = 4;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
			} else if(request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES) {
			} else if(request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES) {
			}
		}
	} else {
		// Client (SIMH)
		DEBUG("dissect_pidp11 adding tree");
		ti = proto_tree_add_item(tree, proto_pidp11, tvb, 0, -1, ENC_NA);
		DEBUG("dissect_pidp11 added tree");

		pidp11_tree = proto_item_add_subtree(ti, ett_top_level);

		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);

		offset += len;
		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_version, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_program_number, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_version, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = 4;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_function, tvb, offset, len, ENC_BIG_ENDIAN);

		if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
			offset = 0x2c;
			len = 4;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		}
	}

	// Column data
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "pidp11");
	col_set_str(pinfo->cinfo, COL_INFO, buf);

	// Return the amount of data we were able to dissect.
	return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_pidp11(void)
{
	module_t	*pidp11_module;

	// Setup list of header fields	See Section 1.5 of README.dissector for details.
	static hf_register_info hf[] = {
		{ &hf_pidp11_sequence_number,		{ "Sequence Number",	"pidp11.seq_num",	FT_UINT32,	BASE_HEX,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_direction,			{ "Direction",		"pidp11.direction",	FT_UINT32,	BASE_NONE,	VALS(RPC_direction), 0, NULL, HFILL } },
		{ &hf_pidp11_rpc_version,		{ "RPC Version",	"pidp11.rpc_vers",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_program_number,		{ "Program Number",	"pidp11.prog_num",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_blinken_version,		{ "Blinken Version",	"pidp11.blink_vers",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_blinken_function,		{ "Blinken Function",	"pidp11.blink_func",	FT_UINT32,	BASE_NONE,	VALS(blinken_function), 0, NULL, HFILL } },
		{ &hf_pidp11_error_code,		{ "Error Code",		"pidp11.error_code",	FT_UINT32,	BASE_HEX,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getinfo_info,		{ "Info",		"pidp11.info",		FT_UINT_STRING,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getpanelinfo_name,		{ "Panel Name",		"pidp11.panel_name",	FT_UINT_STRING,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getpanelinfo_in_count,	{ "Input Count",	"pidp11.in_count",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getpanelinfo_out_count,	{ "Output Count",	"pidp11.out_count",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getpanelinfo_in_bytes,	{ "Input Bytes",	"pidp11.in_bytes",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getpanelinfo_out_bytes,	{ "Output Bytes",	"pidp11.out_bytes",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_index,	{ "Control Index",	"pidp11.control_index",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_name,	{ "Control Name",	"pidp11.control_name",	FT_UINT_STRING,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_input,	{ "Input/Output",	"pidp11.input_output",	FT_UINT32,	BASE_NONE,	VALS(input_output), 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_type,	{ "Control Type",	"pidp11.control_type",	FT_UINT32,	BASE_NONE,	VALS(component_type), 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_radix,	{ "Control Radix",	"pidp11.control_radix",	FT_UINT32,	BASE_NONE,	VALS(component_radix), 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_bits,	{ "Control Bits",	"pidp11.control_bits",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolinfo_bytes,	{ "Control Bytes",	"pidp11.control_bytes",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
	};

	// Setup protocol subtree array.
	static gint *ett[] = {
		&ett_top_level,
	};

	DEBUG("proto_register_pidp11");
	/* Setup protocol expert items */

	/* Register the protocol name and description */
	proto_pidp11 = proto_register_protocol("PiDP-11", "PiDP-11", "pidp-11");

	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_pidp11, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a preferences module (see section 2.6 of README.dissector
	 * for more details). Registration of a prefs callback is not required
	 * if there are no preferences that affect protocol registration (an example
	 * of a preference that would affect registration is a port preference).
	 * If the prefs callback is not needed, use NULL instead of
	 * proto_reg_handoff_pidp11 in the following.
	 */
	pidp11_module = prefs_register_protocol(proto_pidp11, proto_reg_handoff_pidp11);

	/* Register a preferences module under the preferences subtree.
	 * Only use this function instead of prefs_register_protocol (above) if you
	 * want to group preferences of several protocols under one preferences
	 * subtree.
	 *
	 * Argument subtree identifies grouping tree node name, several subnodes can
	 * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
	 * will be accessible under Protocols->OSI->X.500-><PROTOSHORTNAME>
	 * preferences node.
	 */
	pidp11_module = prefs_register_protocol_subtree("", proto_pidp11, proto_reg_handoff_pidp11);

	prefs_register_bool_preference(pidp11_module, "show_hex", "Display numbers in Hex", "Enable to display numerical values in hexadecimal.", &pref_hex);
	prefs_register_uint_preference(pidp11_module, "udp.port", "pidp11 UDP Port", " pidp11 UDP port if other than the default", 10, &udp_port_pref);

	pidp11_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pidp11_hash, pidp11_equal);
}

/* Heuristics test */
static gboolean
test_pidp11(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
	DEBUG("test_pidp11");
	tvb_reported_length(tvb);

	// Check that the packet is long enough for it to belong to us.  The
	// shortest has MIN_LEN bytes of data after the UDP header.
	if(tvb_reported_length(tvb) < MIN_LEN) {
		DEBUG("replen too short");
		return FALSE;
	}

	/* Check that there's enough data present to run the heuristics. If there
	 * isn't, reject the packet; it will probably be dissected as data and if
	 * the user wants it dissected despite it being short they can use the
	 * "Decode-As" functionality. If your heuristic needs to look very deep into
	 * the packet you may not want to require *all* data to be present, but you
	 * should ensure that the heuristic does not access beyond the captured
	 * length of the packet regardless. */
	DEBUG("caplen %d", tvb_captured_length(tvb));
	if(tvb_captured_length(tvb) < MIN_LEN) {
		DEBUG("caplen too short");
		return FALSE;
	}

	/* Fetch some values from the packet header using tvb_get_*(). If these
	 * values are not valid/possible in your protocol then return 0 to give
	 * some other dissector a chance to dissect it. */
	pidp11_sequence_number		= tvb_get_ntohl(tvb, 0x00);
	pidp11_direction		= tvb_get_ntohl(tvb, 0x04);
	pidp11_rpc_version		= tvb_get_ntohl(tvb, 0x08);
	pidp11_program_number		= tvb_get_ntohl(tvb, 0x0c);
	pidp11_blinken_version		= tvb_get_ntohl(tvb, 0x10);
	pidp11_blinken_function		= tvb_get_ntohl(tvb, 0x14);
	DEBUG("seq %x", pidp11_sequence_number);
	DEBUG("dir %d", pidp11_direction);
	DEBUG("rpc %d", pidp11_rpc_version);
	DEBUG("pn %d", pidp11_program_number);
	DEBUG("bv %d", pidp11_blinken_version);
	DEBUG("bf %d", pidp11_blinken_function);

	if(pidp11_direction == 0) {
		// To server.
		if(pidp11_rpc_version != 2) {
			DEBUG("to server but wrong rpc version");
			return FALSE;
		}

		if(pidp11_program_number != 99) {
			DEBUG("to server but wrong program");
			return FALSE;
		}

		if(pidp11_blinken_version != 1) {
			DEBUG("to server but wrong blinken version");
			return FALSE;
		}

		if(!PRIMARY(pidp11_blinken_function) && !SECONDARY(pidp11_blinken_function) && !TERTIARY(pidp11_blinken_function)) {
			DEBUG("to server but illegal function %d", pidp11_blinken_function);
			return FALSE;
		}
		DEBUG("good packet to server");
	} else if(pidp11_direction == 1) {
		// To client.
		if(pidp11_rpc_version != 0) {
			DEBUG("to client but bad rpc version");
			return FALSE;
		}

		if(pidp11_program_number != 0) {
			DEBUG("to client but bad program number");
			return FALSE;
		}

		if(pidp11_blinken_version != 0) {
			DEBUG("to client but bad blinken version");
			return FALSE;
		}

		if(pidp11_blinken_function != 0) {
			DEBUG("to client but bad blinken function");
			return FALSE;
		}

		DEBUG("good packet to client");
	} else {
		DEBUG("bad packet direction");
		return FALSE;
	}

	return TRUE;
}

static guint
get_pidp11_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	DEBUG("get_pidp11_len");
	return (guint) tvb_get_ntohs(tvb, offset + 3);
}

static gboolean
dissect_pidp11_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	DEBUG("dissect_pidp11_heur_udp");
	return (udp_dissect_pdus(tvb, pinfo, tree, 5, test_pidp11, get_pidp11_len, dissect_pidp11, data) != 0);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_pidp11(void)
{
	static gboolean initialized = FALSE;
	static dissector_handle_t pidp11_handle;
	static int current_port;

	DEBUG("proto_reg_handoff_pidp11");
	if (!initialized) {
		/* Use create_dissector_handle() to indicate that
		 * dissect_pidp11() returns the number of bytes it dissected (or 0
		 * if it thinks the packet does not belong to PROTONAME).
		 */
		pidp11_handle = create_dissector_handle(dissect_pidp11, proto_pidp11);
		initialized = TRUE;

	} else {
		/* If you perform registration functions which are dependent upon
		 * prefs then you should de-register everything which was associated
		 * with the previous settings and re-register using the new prefs
		 * settings here. In general this means you need to keep track of
		 * the pidp11_handle and the value the preference had at the time
		 * you registered.  The pidp11_handle value and the value of the
		 * preference can be saved using local statics in this
		 * function (proto_reg_handoff).
		 */
		dissector_delete_uint("udp.port", current_port, pidp11_handle);
	}

	current_port = udp_port_pref;

	heur_dissector_add("udp", dissect_pidp11_heur_udp, "pidp11 over UDP", "pidp11_udp", proto_pidp11, HEURISTIC_ENABLE);
}

// Local Variables:
//   mode: c
//   tab-width: 8
//   c-basic-offset: 8
//   indent-tabs-mode: t
// End:
//
// vim:ts=8:sw=8:sts=8
