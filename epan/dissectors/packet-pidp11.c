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

// When enabling debug, be sure to change the LOG_FILE_PATH to where you want
// the log file to land.
#define ENABLE_DEBUG
#define LOG_FILE_PATH	"/home/sfalco/log.wire"

// Minimum packet length (UDP data portion).
#define MIN_LEN		28

// Buffer size.
#define BUF_LEN		128

// RPC function numbers.
#define RPC_BLINKENLIGHT_API_GETINFO			1
#define RPC_BLINKENLIGHT_API_GETPANELINFO		2
#define RPC_BLINKENLIGHT_API_GETCONTROLINFO		3
#define RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES	4
#define RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES	5
#define RPC_PARAM_GET					100
#define RPC_PARAM_SET					101
#define RPC_TEST_DATA_TO_SERVER				1000
#define RPC_TEST_DATA_FROM_SERVER			1001

// Functions are in three groups.  Here are some convenience macros.
#define PRIMARY_MIN	RPC_BLINKENLIGHT_API_GETINFO
#define PRIMARY_MAX	RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES
#define PRIMARY(a)	(((a) >= PRIMARY_MIN) && ((a) <= PRIMARY_MAX))

#define SECONDARY_MIN	RPC_PARAM_GET
#define SECONDARY_MAX	RPC_PARAM_SET
#define SECONDARY(a)	(((a) >= SECONDARY_MIN) && ((a) <= SECONDARY_MAX))

#define TERTIARY_MIN	RPC_TEST_DATA_TO_SERVER
#define TERTIARY_MAX	RPC_TEST_DATA_FROM_SERVER
#define TERTIARY(a)	(((a) >= TERTIARY_MIN) && ((a) <= TERTIARY_MAX))

// All fields are 32-bits, even though most only use the lowest byte.  The RPC
// messages could be made much more space-efficient...
#define SU		(sizeof(uint32_t))

// Bit mask.
#define MASK(n)		((1 << (n)) - 1)

// Logging mechanism.
#ifdef ENABLE_DEBUG
#define DEBUG(fmt, ... ) logit(__func__, __LINE__, fmt, ##__VA_ARGS__ )

static void logit(
		const char *func,
		int line,
		const char *format,
		...
		)
{
	va_list		ap;
	static FILE	*logfp = 0;

	if(logfp == 0) {
		// Change this path to suit yourself.
		logfp = fopen(LOG_FILE_PATH, "w");
		fprintf(logfp, "opened log\n");
		fflush(logfp);
	}

	if(logfp) {
		fprintf(logfp, "%s %d:", func, line);
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

// For matching message requests and replies.
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

// For looking up control parameters.
struct control_request_key {
	guint32		position;
};

struct control_request_val {
	guint32		position;
	int		is_input;
	char		*pidp11_control_name;
	int		pidp11_control_radix;
	int		pidp11_control_bits;
	int		pidp11_control_bytes;
};

// Map RPC function numbers to names.
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
	{ 8, "Octal"},
	{ 10, "Decimal"},
	{ 16, "Hexadecimal"},
	{ 0, NULL }
};

// Prototypes - these are our primary interface to the main wireshark system.
void proto_reg_handoff_pidp11(void);
void proto_register_pidp11(void);

// Initialize the protocol.
static int		proto_pidp11				= -1;

// Initialize registered fields.
static int		hf_pidp11_sequence_number		= -1;
static int		hf_pidp11_direction			= -1;
static int		hf_pidp11_rpc_version			= -1;
static int		hf_pidp11_program_number		= -1;
static int		hf_pidp11_blinken_version		= -1;
static int		hf_pidp11_blinken_function		= -1;
static int		hf_pidp11_error_code			= -1;
static int		hf_pidp11_getinfo_info			= -1;
static int		hf_pidp11_getpanelinfo_index		= -1;
static int		hf_pidp11_getpanelinfo_name		= -1;
static int		hf_pidp11_getpanelinfo_in_count		= -1;
static int		hf_pidp11_getpanelinfo_out_count	= -1;
static int		hf_pidp11_getpanelinfo_in_bytes		= -1;
static int		hf_pidp11_getpanelinfo_out_bytes	= -1;
static int		hf_pidp11_getcontrolinfo_index		= -1;
static int		hf_pidp11_getcontrolinfo_name		= -1;
static int		hf_pidp11_getcontrolinfo_input		= -1;
static int		hf_pidp11_getcontrolinfo_type		= -1;
static int		hf_pidp11_getcontrolinfo_radix		= -1;
static int		hf_pidp11_getcontrolinfo_bits		= -1;
static int		hf_pidp11_getcontrolinfo_bytes		= -1;
static int		hf_pidp11_getcontrolvalue_bytes		= -1;
static int		hf_pidp11_getcontrolvalue_0		= -1;
static int		hf_pidp11_getcontrolvalue_1		= -1;
static int		hf_pidp11_getcontrolvalue_2		= -1;
static int		hf_pidp11_getcontrolvalue_3		= -1;
static int		hf_pidp11_getcontrolvalue_4		= -1;
static int		hf_pidp11_getcontrolvalue_5		= -1;
static int		hf_pidp11_getcontrolvalue_6		= -1;
static int		hf_pidp11_getcontrolvalue_7		= -1;
static int		hf_pidp11_getcontrolvalue_8		= -1;
static int		hf_pidp11_getcontrolvalue_9		= -1;
static int		hf_pidp11_getcontrolvalue_10		= -1;
static int		hf_pidp11_getcontrolvalue_11		= -1;
static int		hf_pidp11_getcontrolvalue_12		= -1;
static int		hf_pidp11_getcontrolvalue_13		= -1;
static int		hf_pidp11_getcontrolvalue_14		= -1;
static int		hf_pidp11_getcontrolvalue_15		= -1;
static int		hf_pidp11_getcontrolvalue_16		= -1;
static int		hf_pidp11_getcontrolvalue_17		= -1;
static int		hf_pidp11_getcontrolvalue_18		= -1;
static int		hf_pidp11_getcontrolvalue_19		= -1;
static int		hf_pidp11_getcontrolvalue_20		= -1;
static int		hf_pidp11_getcontrolvalue_21		= -1;

// Provide a way to index into these fields.
static int		*slots[] = {
	&hf_pidp11_getcontrolvalue_0,
	&hf_pidp11_getcontrolvalue_1,
	&hf_pidp11_getcontrolvalue_2,
	&hf_pidp11_getcontrolvalue_3,
	&hf_pidp11_getcontrolvalue_4,
	&hf_pidp11_getcontrolvalue_5,
	&hf_pidp11_getcontrolvalue_6,
	&hf_pidp11_getcontrolvalue_7,
	&hf_pidp11_getcontrolvalue_8,
	&hf_pidp11_getcontrolvalue_9,
	&hf_pidp11_getcontrolvalue_10,
	&hf_pidp11_getcontrolvalue_11,
	&hf_pidp11_getcontrolvalue_12,
	&hf_pidp11_getcontrolvalue_13,
	&hf_pidp11_getcontrolvalue_14,
	&hf_pidp11_getcontrolvalue_15,
	&hf_pidp11_getcontrolvalue_16,
	&hf_pidp11_getcontrolvalue_17,
	&hf_pidp11_getcontrolvalue_18,
	&hf_pidp11_getcontrolvalue_19,
	&hf_pidp11_getcontrolvalue_20,
	&hf_pidp11_getcontrolvalue_21,
};
#define NUM_SLOTS	((int)(sizeof(slots) / sizeof(int *)))

// Values of the fields.
static uint32_t		pidp11_sequence_number			= -1;
static int		pidp11_direction			= -1;
static int		pidp11_rpc_version			= -1;
static int		pidp11_program_number			= -1;
static int		pidp11_blinken_version			= -1;
static int		pidp11_blinken_function			= -1;
static int		pidp11_control_index			= -1;

static wmem_map_t *pidp11_request_hash = NULL;
static wmem_map_t *control_request_hash = NULL;

// Initialize the subtree pointer(s).
static gint ett_top_level = -1;

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

// Hashing functions for request/reply packet matching.
static gint
pidp11_equal(gconstpointer v, gconstpointer w)
{
	const struct pidp11_request_key *v1 = (const struct pidp11_request_key *)v;
	const struct pidp11_request_key *v2 = (const struct pidp11_request_key *)w;

	if((v1->conversation == v2->conversation) && (v1->sequence_number == v2->sequence_number)) {
		return 1;
	}

	return 0;
}

static guint
pidp11_hash(gconstpointer v)
{
	const struct pidp11_request_key *key = (const struct pidp11_request_key *)v;
	guint val;

	val = key->conversation + key->sequence_number;

	return val;
}

// Hashing functions for control number/name matching.
static gint
control_equal(gconstpointer v, gconstpointer w)
{
	const struct control_request_key *v1 = (const struct control_request_key *)v;
	const struct control_request_key *v2 = (const struct control_request_key *)w;

	if(v1->position == v2->position) {
		return 1;
	}

	return 0;
}

static guint
control_hash(gconstpointer v)
{
	const struct control_request_key *key = (const struct control_request_key *)v;
	guint val;

	val = key->position;

	return val;
}

// Unfortunately, inputs and outputs are interleaved, so we have to do a linear search for the
// correct element.
static struct control_request_val *
find_label(
		int		is_input,
		int		number
		)
{
	int		i;
	int		in_count;
	int		out_count;

	struct control_request_key control_request_key;
	struct control_request_val *control_request_val;

	DEBUG("finding %s %d", is_input ? "input" : "output", number);
	i = 0;
	in_count = -1;
	out_count = -1;
	while(1) {
		// Find the next entry.
		control_request_key.position = i;
		control_request_val = (struct control_request_val *)wmem_map_lookup(control_request_hash, &control_request_key);

		// Controls are numbered consecutively from zero, so as soon as we find a missing
		// slot, we can give up searching.
		if(!control_request_val) {
			// Not found.
			DEBUG("not found");
			return NULL;
		}

		// Update the appropriate tally.
		if(control_request_val->is_input) {
			in_count++;
		} else {
			out_count++;
		}

		// Inputs and outputs are interleaved, so we have to keep our own counters.
		if(is_input) {
			if(number == in_count) {
				// Found the correct input.
				DEBUG("found input %d at %d", number, i);
				return control_request_val;
			}
		} else {
			if(number == out_count) {
				// Found the correct output.
				DEBUG("found output %d at %d", number, i);
				return control_request_val;
			}
		}

		i++;
	}
}

static void
insert_one_control(
		int		is_input,
		int		number,
		char		*name,
		int		radix,
		int		bits,
		int		bytes
		)
{
	struct control_request_key control_request_key;
	struct control_request_key *new_control_request_key;
	struct control_request_val *control_request_val = NULL;

	char *p;
	int name_len = strlen(name) + 1; // Include space for the null.

	p = (char *)wmem_alloc(wmem_epan_scope(), name_len);
	strncpy(p, name, name_len);

	control_request_key.position = number;
	control_request_val = (struct control_request_val *) wmem_map_lookup(control_request_hash, &control_request_key);

	if(control_request_val) {
		// Control already exists, but might not match, so free it before inserting a new one.
		if(control_request_val->pidp11_control_name) {
			wmem_free(wmem_epan_scope(), control_request_val->pidp11_control_name);
		}
		wmem_map_remove(control_request_hash, &control_request_key);
	}

	DEBUG("%s control %d, %s", is_input ? "input" : "output", control_request_key.position, name);

	new_control_request_key = wmem_new(wmem_epan_scope(), struct control_request_key);
	*new_control_request_key = control_request_key;

	control_request_val = wmem_new(wmem_epan_scope(), struct control_request_val);
	control_request_val->position			= number;
	control_request_val->is_input			= is_input;
	control_request_val->pidp11_control_name	= p;
	control_request_val->pidp11_control_radix	= radix;
	control_request_val->pidp11_control_bits	= bits;
	control_request_val->pidp11_control_bytes	= bytes;

	wmem_map_insert(control_request_hash, new_control_request_key, control_request_val);
}

// In many cases, the capture will not include the RPC_BLINKENLIGHT_API_GETCONTROLINFO messages.
// We cannot associate names with bit-patterns in the RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES
// and RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES unless we have that data.  So, while it is a
// *HACK*, we insert fake names here, based on what we think would have been in the missing
// RPC_BLINKENLIGHT_API_GETCONTROLINFO messages.
//
// If we do capture the RPC_BLINKENLIGHT_API_GETCONTROLINFO messages, those names will replace the
// fake ones that we are adding here.
//
// We add the names in parenthesis here, to indicate that they are inferred, rather than actual.
static void
fake_controls(void)
{
	insert_one_control(TRUE,  0, "(SR)",			8, 22, 3);
	insert_one_control(TRUE,  1, "(LAMPTEST)",		8, 1, 1);
	insert_one_control(TRUE,  2, "(LOAD_ADRS)",		8, 1, 1);
	insert_one_control(TRUE,  3, "(EXAM)",			8, 1, 1);
	insert_one_control(TRUE,  4, "(DEPOSIT)",		8, 1, 1);
	insert_one_control(TRUE,  5, "(CONT)",			8, 1, 1);
	insert_one_control(TRUE,  6, "(HALT)",			8, 1, 1);
	insert_one_control(TRUE,  7, "(S_BUS_CYCLE)",		8, 1, 1);
	insert_one_control(TRUE,  8, "(START)",			8, 1, 1);
	insert_one_control(TRUE,  9, "(ADDR_SELECT)",		8, 3, 1);
	insert_one_control(TRUE, 10, "(DATA_SELECT)",		8, 2, 1);
	insert_one_control(TRUE, 11, "(PANEL_LOCK)",		8, 1, 1);
	insert_one_control(TRUE, 12, "(POWER)",			8, 1, 1);

	insert_one_control(FALSE, 13, "(ADDRESS)",		8, 22, 3);
	insert_one_control(FALSE, 14, "(DATA)",			8, 16, 2);
	insert_one_control(FALSE, 15, "(PARITY_HIGH)",		8, 1, 1);
	insert_one_control(FALSE, 16, "(PARITY_LOW)",		8, 1, 1);
	insert_one_control(FALSE, 17, "(PAR_ERR)",		8, 1, 1);
	insert_one_control(FALSE, 18, "(ADRS_ERR)",		8, 1, 1);
	insert_one_control(FALSE, 19, "(RUN)",			8, 1, 1);
	insert_one_control(FALSE, 20, "(PAUSE)",		8, 1, 1);
	insert_one_control(FALSE, 21, "(MASTER)",		8, 1, 1);
	insert_one_control(FALSE, 22, "(MMR0_MODE)",		8, 3, 1);
	insert_one_control(FALSE, 23, "(DATA_SPACE)",		8, 1, 1);
	insert_one_control(FALSE, 24, "(ADDRESSING_16)",	8, 1, 1);
	insert_one_control(FALSE, 25, "(ADDRESSING_18)",	8, 1, 1);
	insert_one_control(FALSE, 26, "(ADDRESSING_22)",	8, 1, 1);
	insert_one_control(FALSE, 27, "(ADDR_SELECT_FEEDBACK)",	8, 8, 1);
	insert_one_control(FALSE, 28, "(DATA_SELECT_FEEDBACK)",	8, 4, 1);
}

// Code to dissect the packets.
static int
dissect_pidp11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *pidp11_tree;

	conversation_t *conversation;
	struct pidp11_request_key conversation_request_key;
	struct pidp11_request_key *new_conversation_request_key;
	struct pidp11_request_val *conversation_request_val = NULL;

	struct control_request_key control_request_key;
	struct control_request_key *new_control_request_key;
	struct control_request_val *control_request_val = NULL;

	int		i;
	int		j;
	int		k;
	int		k2;

	guint		offset	= 0;
	int		len	= 0;
	char		buf[BUF_LEN];

	int		value_bytes_len;
	uint32_t	*value_bytes_val;
	uint32_t	value;

	DEBUG("begin");

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

	conversation_request_key.conversation = conversation->conv_index;
	conversation_request_key.sequence_number = pidp11_sequence_number;

	conversation_request_val = (struct pidp11_request_val *) wmem_map_lookup(pidp11_request_hash, &conversation_request_key);

	// Only allocate a new hash element when it's a call from SIMH to the panel.
	if(!pinfo->fd->visited) {
		DEBUG("not visited yet");
		if(!conversation_request_val && (pidp11_direction == 0)) {
			DEBUG("no val and dir == to server, inserting request %d", pinfo->num);
			new_conversation_request_key = wmem_new(wmem_epan_scope(), struct pidp11_request_key);
			*new_conversation_request_key = conversation_request_key;

			conversation_request_val = wmem_new(wmem_epan_scope(), struct pidp11_request_val);
			conversation_request_val->req_num			= pinfo->num;
			conversation_request_val->rep_num			= 0;
			conversation_request_val->pidp11_sequence_number	= pidp11_sequence_number;
			conversation_request_val->pidp11_direction		= pidp11_direction;
			conversation_request_val->pidp11_rpc_version		= pidp11_rpc_version;
			conversation_request_val->pidp11_program_number		= pidp11_program_number;
			conversation_request_val->pidp11_blinken_version	= pidp11_blinken_version;
			conversation_request_val->pidp11_blinken_function	= pidp11_blinken_function;

			conversation_request_val->pidp11_control_index	= 0;
			if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
				conversation_request_val->pidp11_control_index = pidp11_control_index;
			}

			wmem_map_insert(pidp11_request_hash, new_conversation_request_key, conversation_request_val);
		}

		if(conversation_request_val && (pidp11_direction == 1)) {
			DEBUG("val exists and dir == to client, inserting reply %d", pinfo->num);
			conversation_request_val->rep_num = pinfo->num;
		}
	}

	if(conversation_request_val && (pidp11_direction == 1)) {
		// Server (Panel)
		DEBUG("val exists, our seq=0x%08x, hashed seq=0x%08x", pidp11_sequence_number, conversation_request_val->pidp11_sequence_number);
		if(PRIMARY(conversation_request_val->pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Server (%s)", low_funcs[conversation_request_val->pidp11_blinken_function - PRIMARY_MIN]);
		} else if(SECONDARY(conversation_request_val->pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Server (%s)", mid_funcs[conversation_request_val->pidp11_blinken_function - SECONDARY_MIN]);
		} else if(TERTIARY(conversation_request_val->pidp11_blinken_function)) {
			g_snprintf(buf, BUF_LEN, "Server (%s)", high_funcs[conversation_request_val->pidp11_blinken_function - TERTIARY_MIN]);
		} else {
			g_snprintf(buf, BUF_LEN, "Server (not matched)");
		}

		DEBUG("adding server tree");
		ti = proto_tree_add_item(tree, proto_pidp11, tvb, 0, -1, ENC_NA);
		DEBUG("added server tree");

		pidp11_tree = proto_item_add_subtree(ti, ett_top_level);

		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);

		offset += len;
		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);

		proto_tree_add_uint(pidp11_tree, hf_pidp11_blinken_function, tvb, 0, 0, conversation_request_val->pidp11_blinken_function);

		if(PRIMARY(conversation_request_val->pidp11_blinken_function)) {
			offset = 0x18;
			len = SU;
			proto_tree_add_uint(pidp11_tree, hf_pidp11_error_code, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			DEBUG("message type %d", conversation_request_val->pidp11_blinken_function);
			if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETINFO) {
				// It would be better to honor the \n chars here.  len is equal to the total length of the
				// string, including the 4-byte size field preceding the string characters.
				//
				// Note that strings are padded with nulls to the next 4-byte boundary.
				len = SU + (((tvb_get_ntohl(tvb, offset) + (SU - 1)) / SU) * SU);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getinfo_info, tvb, offset, SU, ENC_UTF_8 | ENC_BIG_ENDIAN);
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANELINFO) {
				len = SU + (((tvb_get_ntohl(tvb, offset) + (SU - 1)) / SU) * SU);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_name, tvb, offset, SU, ENC_UTF_8 | ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_in_count, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_out_count, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_in_bytes, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_out_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
				proto_tree_add_uint(pidp11_tree, hf_pidp11_getcontrolinfo_index, tvb, 0, 0, conversation_request_val->pidp11_control_index);

				len = SU + (((tvb_get_ntohl(tvb, offset) + (SU - 1)) / SU) * SU);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_name, tvb, offset, SU, ENC_UTF_8 | ENC_BIG_ENDIAN);
				char *name = (char *)tvb_get_string_enc(wmem_epan_scope(), tvb, offset + SU, tvb_get_ntohl(tvb, offset), ENC_UTF_8 | ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_input, tvb, offset, len, ENC_BIG_ENDIAN);
				int is_input = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_type, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_radix, tvb, offset, len, ENC_BIG_ENDIAN);
				int radix = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_bits, tvb, offset, len, ENC_BIG_ENDIAN);
				int bits = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
				int bytes = tvb_get_ntohl(tvb, offset);

				// We have to add each control to a list, so we can find it again, when we interpret the
				// control values.
				control_request_key.position = conversation_request_val->pidp11_control_index;
				control_request_val = (struct control_request_val *) wmem_map_lookup(control_request_hash, &control_request_key);

				if(control_request_val) {
					// Control already exists, but might not match, so free it before inserting a new one.
					if(control_request_val->pidp11_control_name) {
						wmem_free(wmem_epan_scope(), control_request_val->pidp11_control_name);
					}
					wmem_map_remove(control_request_hash, &control_request_key);
				}

				DEBUG("packet=%d inserting %s control %d, %s", pinfo->num, is_input ? "input" : "output", control_request_key.position, name);
				new_control_request_key = wmem_new(wmem_epan_scope(), struct control_request_key);
				*new_control_request_key = control_request_key;

				control_request_val = wmem_new(wmem_epan_scope(), struct control_request_val);
				control_request_val->position			= control_request_key.position;
				control_request_val->is_input			= is_input;
				control_request_val->pidp11_control_name	= name;
				control_request_val->pidp11_control_radix	= radix;
				control_request_val->pidp11_control_bits	= bits;
				control_request_val->pidp11_control_bytes	= bytes;

				wmem_map_insert(control_request_hash, new_control_request_key, control_request_val);
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES) {
				// Nothing to do.
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES) {
				len = SU;
				ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolvalue_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
				value_bytes_len = tvb_get_ntohl(tvb, offset);
				DEBUG("value_bytes_len=%d", value_bytes_len);

				if((value_bytes_val = (uint32_t *)malloc(value_bytes_len * SU))) {
					for(i = 0; i < value_bytes_len; i++) {
						offset += SU;
						value_bytes_val[i] = tvb_get_ntohl(tvb, offset);
						DEBUG("value_bytes_val[%d]=%d", i, value_bytes_val[i]);
					}

					k = 0;
					for(i = 0; TRUE; i++) {
						if(i >= NUM_SLOTS) {
							goto QUIT_INPUT;
						}
						control_request_val = find_label(TRUE, i);
						if(control_request_val) {
							value = 0;
							k2 = k;
							for(j = 0; j < control_request_val->pidp11_control_bytes; j++) {
								if(k >= value_bytes_len) {
									goto QUIT_INPUT;
								}
								value |= value_bytes_val[k++] << (j * 8);
							}
							DEBUG("input %d, position %d, >>>%s<<< = %09o", i, control_request_val->position, control_request_val->pidp11_control_name, value);
							if(control_request_val->pidp11_control_radix == 8) {
								proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x20, SU * control_request_val->pidp11_control_bytes,
										"", "%s = 0%09o", control_request_val->pidp11_control_name, value & MASK(control_request_val->pidp11_control_bits));
							} else if(control_request_val->pidp11_control_radix == 10) {
								proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x20, SU * control_request_val->pidp11_control_bytes,
										"", "%s = %8d", control_request_val->pidp11_control_name, value & MASK(control_request_val->pidp11_control_bits));
							} else if(control_request_val->pidp11_control_radix == 16) {
								proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x20, SU * control_request_val->pidp11_control_bytes,
										"", "%s = 0x%08x", control_request_val->pidp11_control_name, value & MASK(control_request_val->pidp11_control_bits));
							}
						}
					}
				}
				QUIT_INPUT: ;
			}
		}
	} else {
		// Client (SIMH)
		DEBUG("adding client tree");
		ti = proto_tree_add_item(tree, proto_pidp11, tvb, 0, -1, ENC_NA);
		DEBUG("added client tree");

		pidp11_tree = proto_item_add_subtree(ti, ett_top_level);

		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);

		offset += len;
		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_version, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_program_number, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_version, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		ti = proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_function, tvb, offset, len, ENC_BIG_ENDIAN);

		offset = 0x28;
		if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETINFO) {
			// Nothing to do.
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANELINFO) {
			len = SU;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
			len = SU;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			len = SU;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES) {
			len = SU;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			len = SU;
			// This seems to be an error code, because of a common structure.  But it is meaningless here
			// so we skip it.

			offset += len;
			len = SU;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolvalue_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
			value_bytes_len = tvb_get_ntohl(tvb, offset);
			DEBUG("value_bytes_len=%d", value_bytes_len);

			if((value_bytes_val = (uint32_t *)malloc(value_bytes_len * SU))) {
				for(i = 0; i < value_bytes_len; i++) {
					offset += SU;
					value_bytes_val[i] = tvb_get_ntohl(tvb, offset);
					DEBUG("value_bytes_val[%d]=%d", i, value_bytes_val[i]);
				}

				k = 0;
				for(i = 0; TRUE; i++) {
					if(i >= NUM_SLOTS) {
						goto QUIT_OUTPUT;
					}
					control_request_val = find_label(FALSE, i);
					if(control_request_val) {
						value = 0;
						k2 = k;
						for(j = 0; j < control_request_val->pidp11_control_bytes; j++) {
							if(k >= value_bytes_len) {
								goto QUIT_OUTPUT;
							}
							value |= value_bytes_val[k++] << (j * 8);
						}
						DEBUG("output %d, position %d, >>>%s<<< = %09o", i, control_request_val->position, control_request_val->pidp11_control_name, value);
						if(control_request_val->pidp11_control_radix == 8) {
							proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x34, SU * control_request_val->pidp11_control_bytes,
									"", "%s = 0%09o", control_request_val->pidp11_control_name, value & MASK(control_request_val->pidp11_control_bits));
						} else if(control_request_val->pidp11_control_radix == 10) {
							proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x34, SU * control_request_val->pidp11_control_bytes,
									"", "%s = %8d", control_request_val->pidp11_control_name, value & MASK(control_request_val->pidp11_control_bits));
						} else if(control_request_val->pidp11_control_radix == 16) {
							proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x34, SU * control_request_val->pidp11_control_bytes,
									"", "%s = 0x%08x", control_request_val->pidp11_control_name, value & MASK(control_request_val->pidp11_control_bits));
						}
					}
				}
			}
			QUIT_OUTPUT: ;
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES) {
			len = SU;
			ti = proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		}
	}

	// Column data
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "pidp11");
	col_set_str(pinfo->cinfo, COL_INFO, buf);

	// Return the amount of data we were able to dissect.
	return tvb_captured_length(tvb);
}
// Register the protocol with Wireshark.
void
proto_register_pidp11(void)
{
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
		{ &hf_pidp11_getpanelinfo_index,	{ "Panel Index",	"pidp11.panel_index",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
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
		{ &hf_pidp11_getcontrolvalue_bytes,	{ "Control Bytes",	"pidp11.control_bytes",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_0,		{ "Control 0",		"pidp11.control_0",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_1,		{ "Control 1",		"pidp11.control_1",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_2,		{ "Control 2",		"pidp11.control_2",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_3,		{ "Control 3",		"pidp11.control_3",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_4,		{ "Control 4",		"pidp11.control_4",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_5,		{ "Control 5",		"pidp11.control_5",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_6,		{ "Control 6",		"pidp11.control_6",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_7,		{ "Control 7",		"pidp11.control_7",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_8,		{ "Control 8",		"pidp11.control_8",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_9,		{ "Control 9",		"pidp11.control_9",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_10,	{ "Control 10",		"pidp11.control_10",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_11,	{ "Control 11",		"pidp11.control_11",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_12,	{ "Control 12",		"pidp11.control_12",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_13,	{ "Control 13",		"pidp11.control_13",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_14,	{ "Control 14",		"pidp11.control_14",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_15,	{ "Control 15",		"pidp11.control_15",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_16,	{ "Control 16",		"pidp11.control_16",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_17,	{ "Control 17",		"pidp11.control_17",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_18,	{ "Control 18",		"pidp11.control_18",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_19,	{ "Control 19",		"pidp11.control_19",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_20,	{ "Control 20",		"pidp11.control_20",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_getcontrolvalue_21,	{ "Control 21",		"pidp11.control_21",	FT_STRINGZ,	BASE_NONE,	NULL, 0, NULL, HFILL } },
	};

	// Setup protocol subtree array.
	static gint *ett[] = {
		&ett_top_level,
	};

	DEBUG("start");

	// Register the protocol name and description.
	proto_pidp11 = proto_register_protocol("PiDP-11", "PiDP-11", "pidp-11");

	// Register the header fields and subtrees.
	proto_register_field_array(proto_pidp11, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	pidp11_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_epan_scope(), pidp11_hash, pidp11_equal);
	control_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_epan_scope(), control_hash, control_equal);

	// In case we don't learn these from the packet stream, start with some likely defaults.
	fake_controls();
}

// Heuristics test.
static gboolean
test_pidp11(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
	DEBUG("start");
	tvb_reported_length(tvb);

	// Check that the packet is long enough for it to belong to us.  The
	// shortest has MIN_LEN bytes of data after the UDP header.
	if(tvb_reported_length(tvb) < MIN_LEN) {
		DEBUG("replen too short");
		return FALSE;
	}

	// Check that there's enough data present to run the heuristics. If
	// there isn't, reject the packet.
	DEBUG("caplen %d", tvb_captured_length(tvb));
	if(tvb_captured_length(tvb) < MIN_LEN) {
		DEBUG("caplen too short");
		return FALSE;
	}

	// Fetch some values from the packet header.
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
	DEBUG("start");
	return (guint) tvb_get_ntohs(tvb, offset + 3);
}

static gboolean
dissect_pidp11_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	DEBUG("start");
	return (udp_dissect_pdus(tvb, pinfo, tree, 5, test_pidp11, get_pidp11_len, dissect_pidp11, data) != 0);
}

// Register for handoffs.
void
proto_reg_handoff_pidp11(void)
{
	static gboolean initialized = FALSE;

	DEBUG("start");
	if (!initialized) {
		create_dissector_handle(dissect_pidp11, proto_pidp11);
		heur_dissector_add("udp", dissect_pidp11_heur_udp, "pidp11 over UDP", "pidp11_udp", proto_pidp11, HEURISTIC_ENABLE);
		initialized = TRUE;
	}
}

// Local Variables:
//   mode: c
//   tab-width: 8
//   c-basic-offset: 8
//   indent-tabs-mode: t
// End:
//
// vim:ts=8:sw=8:sts=8
