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
#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/dissectors/packet-udp.h>

// When enabling debug, be sure to change the LOG_FILE_PATH to where you want
// the log file to land.
#undef ENABLE_DEBUG
#define LOG_FILE_PATH	"/home/sfalco/log.wire"

// Minimum packet length (UDP data portion).
#define MIN_LEN		28

// Buffer size.
#define BUF_LEN		128

// Maximum number of switches and LEDs that we handle.
#define MAX_CONTROLS	30

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

#define RPC_PARAM_CLASS_BUS				1
#define RPC_PARAM_CLASS_PANEL				2
#define RPC_PARAM_CLASS_CONTROL				3

#define RPC_PARAM_HANDLE_PANEL_BLINKENBOARDS_STATE		1
#define RPC_PARAM_VALUE_PANEL_BLINKENBOARDS_STATE_OFF		0
#define RPC_PARAM_VALUE_PANEL_BLINKENBOARDS_STATE_TRISTATE	1
#define RPC_PARAM_VALUE_PANEL_BLINKENBOARDS_STATE_ACTIVE	2

#define RPC_PARAM_HANDLE_PANEL_MODE			2
#define RPC_PARAM_VALUE_PANEL_MODE_NORMAL		0
#define RPC_PARAM_VALUE_PANEL_MODE_LAMPTEST		1
#define RPC_PARAM_VALUE_PANEL_MODE_ALLTEST		2
#define RPC_PARAM_VALUE_PANEL_MODE_POWERLESS		3

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

// General bit mask.
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

// We store control parameters here, for use in get/set message decoding.
static struct control {
	int		valid;
	int		is_input;
	char		*name;
	int		radix;
	int		bits;
	int		bytes;
} controls[MAX_CONTROLS];

// To avoid wasting time doing linear searches, we keep a cache of the
// control offsets.
struct control_cache {
	int		valid;
	struct control	*p;
};
static struct control_cache input_controls[MAX_CONTROLS];
static struct control_cache output_controls[MAX_CONTROLS];

// Map RPC function numbers to names.
static const value_string blinken_function[] = {
	{ RPC_BLINKENLIGHT_API_GETINFO,			"RPC_BLINKENLIGHT_API_GETINFO" },
	{ RPC_BLINKENLIGHT_API_GETPANELINFO,		"RPC_BLINKENLIGHT_API_GETPANELINFO" },
	{ RPC_BLINKENLIGHT_API_GETCONTROLINFO,		"RPC_BLINKENLIGHT_API_GETCONTROLINFO" },
	{ RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES,	"RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES" },
	{ RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES,	"RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES" },
	{ RPC_PARAM_GET,				"RPC_PARAM_GET" },
	{ RPC_PARAM_SET,				"RPC_PARAM_SET" },
	{ RPC_TEST_DATA_TO_SERVER,			"RPC_TEST_DATA_TO_SERVER" },
	{ RPC_TEST_DATA_FROM_SERVER,			"RPC_TEST_DATA_FROM_SERVER" },
	{ 0,	NULL }
};

// VALS() tables.
static const value_string RPC_direction[] = {
	{ 0, "Request from SIMH to Panel" },
	{ 1, "Reply from Panel to SIMH" },
	{ 0, NULL }
};

static const value_string input_output[] = {
	{ 0, "Output" },
	{ 1, "Input" },
	{ 0, NULL }
};

static const value_string component_type[] = {
	{ 1, "Switch" },
	{ 2, "LED" },
	{ 0, NULL }
};

static const value_string component_radix[] = {
	{ 8, "Octal" },
	{ 10, "Decimal" },
	{ 16, "Hexadecimal" },
	{ 0, NULL }
};

static const value_string error_code[] = {
	{ 0, "RPC_ERR_OK" },
	{ 1, "RPC_ERR_PARAM_ILL_CLASS" },
	{ 2, "RPC_ERR_PARAM_ILL_OBJECT" },
	{ 3, "RPC_ERR_PARAM_ILL_PARAM" },
	{ 0, NULL }
};

static const value_string param_class[] = {
	{ 1, "RPC_PARAM_CLASS_BUS" },
	{ 2, "RPC_PARAM_CLASS_PANEL" },
	{ 3, "RPC_PARAM_CLASS_CONTROL" },
	{ 0, NULL }
};

static const value_string param_handle[] = {
	{ 1, "RPC_PARAM_HANDLE_PANEL_BLINKENBOARDS_STATE" },
	{ 2, "RPC_PARAM_HANDLE_PANEL_MODE" },
	{ 0, NULL }
};

static const value_string state_param_value[] = {
	{ 0, "RPC_PARAM_VALUE_PANEL_BLINKENBOARDS_STATE_OFF" },
	{ 1, "RPC_PARAM_VALUE_PANEL_BLINKENBOARDS_STATE_TRISTATE" },
	{ 2, "RPC_PARAM_VALUE_PANEL_BLINKENBOARDS_STATE_ACTIVE" },
	{ 0, NULL }
};

static const value_string mode_param_value[] = {
	{ 0, "RPC_PARAM_VALUE_PANEL_MODE_NORMAL" },
	{ 1, "RPC_PARAM_VALUE_PANEL_MODE_LAMPTEST" },
	{ 2, "RPC_PARAM_VALUE_PANEL_MODE_ALLTEST" },
	{ 3, "RPC_PARAM_VALUE_PANEL_MODE_POWERLESS" },
	{ 0, NULL }
};

// Some strings for our INFO field.
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
static int		hf_pidp11_rpc_param_get_obj_class	= -1;
static int		hf_pidp11_rpc_param_get_obj_handle	= -1;
static int		hf_pidp11_rpc_param_get_param_handle	= -1;
static int		hf_pidp11_rpc_param_get_state_value	= -1;
static int		hf_pidp11_rpc_param_get_mode_value	= -1;

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
};
#define NUM_SLOTS	((int)(sizeof(slots) / sizeof(int *)))

// Initialize the subtree pointer.
static gint ett_pidp11 = -1;

// Use a hash table to associate request/reply packets.
static wmem_map_t *pidp11_request_hash = NULL;

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

// Unfortunately, inputs and outputs are interleaved, so we have to do a
// linear search for the correct element.  We keep a cache of found items
// to help avoid searches wherever possible.
static struct control *
find_label(
		int		is_input,
		int		number
		)
{
	int			i;
	int			in_count;
	int			out_count;

	struct control		*pVal;
	struct control_cache	*p;

	DEBUG("finding %s %d", is_input ? "input" : "output", number);

	if(number >= MAX_CONTROLS) {
		DEBUG("number exceeds MAX_CONTROLS");
		return NULL;
	}

	// First check the cache.
	if(is_input) {
		p = &input_controls[number];
	} else {
		p = &output_controls[number];
	}
	if(p->valid) {
		DEBUG("found in cache");
		return p->p;
	}
	DEBUG("not found in cache");

	// Not found in the cache - we have to search for it.
	in_count = -1;
	out_count = -1;
	for(i = 0; i < MAX_CONTROLS; i++) {
		// Test the next entry.
		pVal = &controls[i];
		if(pVal->valid != TRUE) {
			// Skip empty slots.
			continue;
		}

		// There is something in this slot.  Update the appropriate
		// tally.  Inputs and outputs are interleaved, so we have to
		// keep our own counters.
		if(pVal->is_input) {
			in_count++;
		} else {
			out_count++;
		}

		if(is_input) {
			if(number == in_count) {
				// Found the correct input.  Insert it into
				// the cache, and return it.
				DEBUG("found input %d at %d, add to cache", number, i);
				p->valid = TRUE;
				p->p = pVal;
				return pVal;
			}
		} else {
			if(number == out_count) {
				// Found the correct output.  Insert it into
				// the cache, and return it.
				DEBUG("found output %d at %d, add to cache", number, i);
				p->valid = TRUE;
				p->p = pVal;
				return pVal;
			}
		}
	}

	DEBUG("not found");
	return NULL;
}

static int
insert_one_control(
		int		is_input,
		int		slot,
		char		*name,
		int		radix,
		int		bits,
		int		bytes
		)
{
	struct control *pVal;
	int i;

	DEBUG("%s control %d, %s", is_input ? "input" : "output", slot, name);

	if(slot >= MAX_CONTROLS) {
		DEBUG("Slot out of range - cannot insert");
		return 0;
	}
	pVal = &controls[slot];

	// Clear caches, as the entries may have changed.
	for(i = 0; i < MAX_CONTROLS; i++) {
		input_controls[i].valid = FALSE;
		output_controls[i].valid = FALSE;
	}
	DEBUG("cleared cache because of insert");

	if(pVal->valid == TRUE) {
		// Slot is already occupied, so free the old name before
		// attaching a new one.
		if(pVal->name) {
			wmem_free(wmem_epan_scope(), pVal->name);
		}
	}

	// Store the parameters.
	pVal->valid	= TRUE;
	pVal->is_input	= is_input;
	pVal->name	= name;
	pVal->radix	= radix;
	pVal->bits	= bits;
	pVal->bytes	= bytes;

	return 1;
}

static int
allocate_and_insert_one_control(
		int		is_input,
		int		slot,
		char		*name,
		int		radix,
		int		bits,
		int		bytes
		)
{
	int name_len = strlen(name) + 1; // Include space for the null.
	char *p = (char *)wmem_alloc(wmem_epan_scope(), name_len);

	if(!p) {
		return 0;
	}
	strncpy(p, name, name_len);

	return insert_one_control(is_input, slot, p, radix, bits, bytes);
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
// We add the names in parenthesis, to indicate that they are inferred, rather than actual.
//
// It is important that the order of the assignments here match those in the pidp11 source code.
// Otherwise, if we had a partial capture of RPC_BLINKENLIGHT_API_GETCONTROLINFO messages, we
// might replace the wrong entry.  See register_controls() in 11_pidp_server/pidp11/main.c,
// and of course if that code changes, we'll have to change too.
//
// NB: I considered dispensing with the slot field, but that won't work.  Wireshark can process
// the packets in any order, so we must have the slot number to keep things straight.
//
// It would have been better if RPC_BLINKENLIGHT_API_GETCONTROLINFO was split into two different
// message types - one for input and one for output - with separate "number spaces".  Then there
// would be no interleaving, and the slot numbers would directly map to the offsets in the
// RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES and RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES
// messages.
static void
fake_controls(void)
{
	allocate_and_insert_one_control(TRUE,   0, "(SR)",			8, 22, 3);
	allocate_and_insert_one_control(TRUE,   1, "(LAMPTEST)",		8, 1, 1);
	allocate_and_insert_one_control(TRUE,   2, "(LOAD_ADRS)",		8, 1, 1);
	allocate_and_insert_one_control(TRUE,   3, "(EXAM)",			8, 1, 1);
	allocate_and_insert_one_control(TRUE,   4, "(DEPOSIT)",			8, 1, 1);
	allocate_and_insert_one_control(TRUE,   5, "(CONT)",			8, 1, 1);
	allocate_and_insert_one_control(TRUE,   6, "(HALT)",			8, 1, 1);
	allocate_and_insert_one_control(TRUE,   7, "(S_BUS_CYCLE)",		8, 1, 1);
	allocate_and_insert_one_control(TRUE,   8, "(START)",			8, 1, 1);
	allocate_and_insert_one_control(FALSE,  9, "(ADDRESS)",			8, 22, 3);
	allocate_and_insert_one_control(FALSE, 10, "(DATA)",			8, 16, 2);
	allocate_and_insert_one_control(FALSE, 11, "(PARITY_HIGH)",		8, 1, 1);
	allocate_and_insert_one_control(FALSE, 12, "(PARITY_LOW)",		8, 1, 1);
	allocate_and_insert_one_control(FALSE, 13, "(PAR_ERR)",			8, 1, 1);
	allocate_and_insert_one_control(FALSE, 14, "(ADRS_ERR)",		8, 1, 1);
	allocate_and_insert_one_control(FALSE, 15, "(RUN)",			8, 1, 1);
	allocate_and_insert_one_control(FALSE, 16, "(PAUSE)",			8, 1, 1);
	allocate_and_insert_one_control(FALSE, 17, "(MASTER)",			8, 1, 1);
	allocate_and_insert_one_control(FALSE, 18, "(MMR0_MODE)",		8, 3, 1);
	allocate_and_insert_one_control(FALSE, 19, "(DATA_SPACE)",		8, 1, 1);
	allocate_and_insert_one_control(FALSE, 20, "(ADDRESSING_16)",		8, 1, 1);
	allocate_and_insert_one_control(FALSE, 21, "(ADDRESSING_18)",		8, 1, 1);
	allocate_and_insert_one_control(FALSE, 22, "(ADDRESSING_22)",		8, 1, 1);
	allocate_and_insert_one_control(TRUE,  23, "(ADDR_SELECT)",		8, 3, 1);
	allocate_and_insert_one_control(TRUE,  24, "(DATA_SELECT)",		8, 2, 1);
	allocate_and_insert_one_control(FALSE, 25, "(ADDR_SELECT_FEEDBACK)",	8, 8, 1);
	allocate_and_insert_one_control(FALSE, 26, "(DATA_SELECT_FEEDBACK)",	8, 4, 1);
	allocate_and_insert_one_control(TRUE,  27, "(PANEL_LOCK)",		8, 1, 1);
	allocate_and_insert_one_control(TRUE,  28, "(POWER)",			8, 1, 1);
}

// Code to dissect the packets.
static int
dissect_pidp11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	// This is our subtree.
	proto_tree *pidp11_tree;

	conversation_t *conversation;
	struct pidp11_request_key conversation_request_key;
	struct pidp11_request_key *new_conversation_request_key;
	struct pidp11_request_val *conversation_request_val = NULL;

	struct control *pVal = NULL;

	int		i;
	int		j;
	int		k;
	int		k2;
	int		m;

	guint		offset	= 0;
	int		len	= 0;
	char		buf[BUF_LEN];

	int		value_bytes_len;
	uint32_t	*value_bytes_val;
	uint32_t	value;

	uint32_t	pidp11_sequence_number;
	int		pidp11_direction;
	int		pidp11_rpc_version;
	int		pidp11_program_number;
	int		pidp11_blinken_version;
	int		pidp11_blinken_function;

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
				conversation_request_val->pidp11_control_index = tvb_get_ntohl(tvb, 0x2c);
			}

			wmem_map_insert(pidp11_request_hash, new_conversation_request_key, conversation_request_val);
		}

		if(conversation_request_val && (pidp11_direction == 1)) {
			DEBUG("val exists and dir == to client, inserting reply %d", pinfo->num);
			conversation_request_val->rep_num = pinfo->num;
		}
	}

	DEBUG("adding subtree");
	proto_item *ti = proto_tree_add_item(tree, proto_pidp11, tvb, 0, -1, ENC_NA);
	pidp11_tree = proto_item_add_subtree(ti, ett_pidp11);
	DEBUG("added subtree");

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
			REPORT_DISSECTOR_BUG("Unrecognized packet function %d", conversation_request_val->pidp11_blinken_function);
			g_snprintf(buf, BUF_LEN, "unknown");
		}

		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);

		offset += len;
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);

		proto_tree_add_uint(pidp11_tree, hf_pidp11_blinken_function, tvb, 0, 0, conversation_request_val->pidp11_blinken_function);

		if(PRIMARY(conversation_request_val->pidp11_blinken_function) || SECONDARY(conversation_request_val->pidp11_blinken_function)) {
			offset = 0x18;
			len = SU;
			proto_tree_add_uint(pidp11_tree, hf_pidp11_error_code, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			DEBUG("message type %d", conversation_request_val->pidp11_blinken_function);
			if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETINFO) {
				// Note that strings are padded with nulls to the next 4-byte boundary, so
				// we have to round "len" up, as well as adding in an extra "SU" to account
				// for the length word prefix.
				int data_len = tvb_get_ntohl(tvb, offset);
				len = SU + (((data_len + (SU - 1)) / SU) * SU);

				// Allocate space for the text.
				char *info = (char *)wmem_alloc(wmem_epan_scope(), data_len + 1);

				// Get a copy - we have to modify it to break it at newline boundaries.
				tvb_memcpy(tvb, info, offset + SU, data_len);
				info[data_len] = 0;

				// Scan the string, and chop/display it at the newline boundaries.
				int start = offset + SU;
				int str_len;
				char *p, *q;
				m = 0;
				for(p = q = info; *p != 0; p++) {
					if(*p == '\n') {
						*p = 0;
						str_len = (p + 1) - q; // p hasn't incremented yet, so add one.
						proto_tree_add_string_format(pidp11_tree, *slots[m++], tvb, start, str_len, "", "%s", q);
						start += str_len;
						q = (p + 1);
						if(m >= NUM_SLOTS) {
							break;
						}
					}
				}

				// Done with the copy.
				wmem_free(wmem_epan_scope(), info);
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANELINFO) {
				len = SU + (((tvb_get_ntohl(tvb, offset) + (SU - 1)) / SU) * SU);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_name, tvb, offset, SU, ENC_UTF_8 | ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_in_count, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_out_count, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_in_bytes, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_out_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
				proto_tree_add_uint(pidp11_tree, hf_pidp11_getcontrolinfo_index, tvb, 0, 0, conversation_request_val->pidp11_control_index);

				len = SU + (((tvb_get_ntohl(tvb, offset) + (SU - 1)) / SU) * SU);
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_name, tvb, offset, SU, ENC_UTF_8 | ENC_BIG_ENDIAN);
				char *name = (char *)tvb_get_string_enc(wmem_epan_scope(), tvb, offset + SU, tvb_get_ntohl(tvb, offset), ENC_UTF_8 | ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_input, tvb, offset, len, ENC_BIG_ENDIAN);
				int is_input = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_type, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_radix, tvb, offset, len, ENC_BIG_ENDIAN);
				int radix = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_bits, tvb, offset, len, ENC_BIG_ENDIAN);
				int bits = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
				int bytes = tvb_get_ntohl(tvb, offset);

				// We have to add each control to a list, so we can find it again, when we interpret the
				// control values.
				if(!insert_one_control(is_input, conversation_request_val->pidp11_control_index, name, radix, bits, bytes)) {
					REPORT_DISSECTOR_BUG("No room to insert %s", name);
					wmem_free(wmem_epan_scope(), name);
				}
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES) {
				// Nothing to do.
			} else if(conversation_request_val->pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES) {
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolvalue_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
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
							DEBUG("No more hf slots");
							goto QUIT_INPUT;
						}
						pVal = find_label(TRUE, i);
						if(pVal) {
							value = 0;
							k2 = k;
							for(j = 0; j < pVal->bytes; j++) {
								if(k >= value_bytes_len) {
									DEBUG("No more data");
									goto QUIT_INPUT;
								}
								value |= value_bytes_val[k++] << (j * 8);
							}
							DEBUG("input %d, >>>%s<<< = %09o", i, pVal->name, value);
							if(pVal->radix == 8) {
								proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x20, SU * pVal->bytes,
										"", "%s = 0%09o", pVal->name, value & MASK(pVal->bits));
							} else if(pVal->radix == 10) {
								proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x20, SU * pVal->bytes,
										"", "%s = %8d", pVal->name, value & MASK(pVal->bits));
							} else if(pVal->radix == 16) {
								proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x20, SU * pVal->bytes,
										"", "%s = 0x%08x", pVal->name, value & MASK(pVal->bits));
							} else {
								REPORT_DISSECTOR_BUG("Unknown radix %d", pVal->radix);
							}
						}
					}
				}
				QUIT_INPUT: ;
			} else if(conversation_request_val->pidp11_blinken_function == RPC_PARAM_GET) {
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_obj_class, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_obj_handle, tvb, offset, len, ENC_BIG_ENDIAN);

				offset += len;
				len = SU;
				proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_param_handle, tvb, offset, len, ENC_BIG_ENDIAN);
				int handle = tvb_get_ntohl(tvb, offset);

				offset += len;
				len = SU;
				if(handle == RPC_PARAM_HANDLE_PANEL_BLINKENBOARDS_STATE) {
					proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_state_value, tvb, offset, len, ENC_BIG_ENDIAN);
				} else if(handle == RPC_PARAM_HANDLE_PANEL_MODE) {
					proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_mode_value, tvb, offset, len, ENC_BIG_ENDIAN);
				}
			}
		}
	} else {
		// Client (SIMH)
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);

		offset += len;
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_version, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_program_number, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_version, tvb, offset, len, ENC_BIG_ENDIAN);

		offset += len;
		len = SU;
		proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_function, tvb, offset, len, ENC_BIG_ENDIAN);

		offset = 0x28;
		if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETINFO) {
			// Nothing to do.
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANELINFO) {
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETCONTROLINFO) {
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES) {
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			len = SU;
			// This seems to be an error code, because of a common structure.  But it is meaningless here
			// so we skip it.

			offset += len;
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_getcontrolvalue_bytes, tvb, offset, len, ENC_BIG_ENDIAN);
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
						// We have run out of hf slots.
						DEBUG("No more hf slots");
						goto QUIT_OUTPUT;
					}
					pVal = find_label(FALSE, i);
					if(pVal) {
						value = 0;
						k2 = k;
						for(j = 0; j < pVal->bytes; j++) {
							if(k >= value_bytes_len) {
								DEBUG("No more data");
								goto QUIT_OUTPUT;
							}
							value |= value_bytes_val[k++] << (j * 8);
						}
						DEBUG("output %d, >>>%s<<< = %09o", i, pVal->name, value);
						if(pVal->radix == 8) {
							proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x34, SU * pVal->bytes,
									"", "%s = 0%09o", pVal->name, value & MASK(pVal->bits));
						} else if(pVal->radix == 10) {
							proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x34, SU * pVal->bytes,
									"", "%s = %8d", pVal->name, value & MASK(pVal->bits));
						} else if(pVal->radix == 16) {
							proto_tree_add_string_format(pidp11_tree, *slots[i], tvb, SU * k2 + 0x34, SU * pVal->bytes,
									"", "%s = 0x%08x", pVal->name, value & MASK(pVal->bits));
						} else {
							REPORT_DISSECTOR_BUG("Unknown radix %d", pVal->radix);
						}
					}
				}
			}
			QUIT_OUTPUT: ;
		} else if(pidp11_blinken_function == RPC_BLINKENLIGHT_API_GETPANEL_CONTROLVALUES) {
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_getpanelinfo_index, tvb, offset, len, ENC_BIG_ENDIAN);
		} else if(pidp11_blinken_function == RPC_PARAM_GET) {
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_obj_class, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_obj_handle, tvb, offset, len, ENC_BIG_ENDIAN);

			offset += len;
			len = SU;
			proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_param_get_param_handle, tvb, offset, len, ENC_BIG_ENDIAN);
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
	// Setup list of header fields.  Unfortunately, we cannot add these dynamically,
	// so we have to create a fixed number of "hf_pidp11_getcontrolvalue" elements.
	// We need 16 of them, because there are 16 outputs (and 13 inputs).
	static hf_register_info hf[] = {
		{ &hf_pidp11_sequence_number,		{ "Sequence Number",	"pidp11.seq_num",	FT_UINT32,	BASE_HEX,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_direction,			{ "Direction",		"pidp11.direction",	FT_UINT32,	BASE_NONE,	VALS(RPC_direction), 0, NULL, HFILL } },
		{ &hf_pidp11_rpc_version,		{ "RPC Version",	"pidp11.rpc_vers",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_program_number,		{ "Program Number",	"pidp11.prog_num",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_blinken_version,		{ "Blinken Version",	"pidp11.blink_vers",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_blinken_function,		{ "Blinken Function",	"pidp11.blink_func",	FT_UINT32,	BASE_NONE,	VALS(blinken_function), 0, NULL, HFILL } },
		{ &hf_pidp11_error_code,		{ "Error Code",		"pidp11.error_code",	FT_UINT32,	BASE_NONE,	VALS(error_code), 0, NULL, HFILL } },
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
		{ &hf_pidp11_rpc_param_get_obj_class,	{ "Object Class",	"pidp11.obj_class",	FT_UINT32,	BASE_NONE,	VALS(param_class), 0, NULL, HFILL } },
		{ &hf_pidp11_rpc_param_get_obj_handle,	{ "Object Handle",	"pidp11.obj_handle",	FT_UINT32,	BASE_DEC,	NULL, 0, NULL, HFILL } },
		{ &hf_pidp11_rpc_param_get_param_handle,{ "Parameter Handle",	"pidp11.param_handle",	FT_UINT32,	BASE_NONE,	VALS(param_handle), 0, NULL, HFILL } },
		{ &hf_pidp11_rpc_param_get_state_value,	{ "State Value",	"pidp11.state_value",	FT_UINT32,	BASE_NONE,	VALS(state_param_value), 0, NULL, HFILL } },
		{ &hf_pidp11_rpc_param_get_mode_value,	{ "Mode Value",		"pidp11.mode_value",	FT_UINT32,	BASE_NONE,	VALS(mode_param_value), 0, NULL, HFILL } },
	};

	// Setup protocol subtree array.
	static gint *ett[] = {
		&ett_pidp11,
	};

	DEBUG("start");

	// Register the protocol name and description.
	proto_pidp11 = proto_register_protocol("PiDP-11", "PiDP-11", "pidp-11");

	// Register the header fields and subtrees.
	proto_register_field_array(proto_pidp11, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	pidp11_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_epan_scope(), pidp11_hash, pidp11_equal);

	// In case we don't learn these from the packet stream, start with some likely defaults.
	fake_controls();
}

// Heuristics test.
static gboolean
test_pidp11(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
	guint		l;
	int		pidp11_direction;
	int		pidp11_rpc_version;
	int		pidp11_program_number;
	int		pidp11_blinken_version;
	int		pidp11_blinken_function;

	DEBUG("start");

	// Check that the packet is long enough for it to belong to us.  The
	// shortest has MIN_LEN bytes of data after the UDP header.
	if((l = tvb_reported_length(tvb)) < MIN_LEN) {
		DEBUG("reported length too short, %d < %d", l, MIN_LEN);
		return FALSE;
	}

	// Check that there's enough data present to run the heuristics.  If
	// there isn't, reject the packet.
	if((l = tvb_captured_length(tvb)) < MIN_LEN) {
		DEBUG("captured length too short, %d < %d", l, MIN_LEN);
		return FALSE;
	}

	// Fetch some values from the packet header.
	pidp11_direction		= tvb_get_ntohl(tvb, 0x04);
	pidp11_rpc_version		= tvb_get_ntohl(tvb, 0x08);
	pidp11_program_number		= tvb_get_ntohl(tvb, 0x0c);
	pidp11_blinken_version		= tvb_get_ntohl(tvb, 0x10);
	pidp11_blinken_function		= tvb_get_ntohl(tvb, 0x14);

	if(pidp11_direction == 0) {
		// To server.
		if(pidp11_rpc_version != 2) {
			DEBUG("to server but wrong rpc version, %d != %d", pidp11_rpc_version, 2);
			return FALSE;
		}

		if(pidp11_program_number != 99) {
			DEBUG("to server but wrong program, %d != %d", pidp11_program_number, 99);
			return FALSE;
		}

		if(pidp11_blinken_version != 1) {
			DEBUG("to server but wrong blinken version, %d != %d", pidp11_blinken_version, 1);
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
			DEBUG("to client but wrong rpc version, %d != %d", pidp11_rpc_version, 0);
			return FALSE;
		}

		if(pidp11_program_number != 0) {
			DEBUG("to client but wrong program, %d != %d", pidp11_program_number, 0);
			return FALSE;
		}

		if(pidp11_blinken_version != 0) {
			DEBUG("to client but wrong blinken version, %d != %d", pidp11_blinken_version, 0);
			return FALSE;
		}

		if(pidp11_blinken_function != 0) {
			DEBUG("to client but bad blinken function, %d != %d", pidp11_blinken_function, 0);
			return FALSE;
		}

		DEBUG("good packet to client");
	} else {
		DEBUG("bad packet direction, %d, should be 0 or 1", pidp11_direction);
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
