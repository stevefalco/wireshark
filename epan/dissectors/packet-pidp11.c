/* packet-pidp11.c
 * Routines for pidp11 dissection
 * Copyright 2020, Steven A. Falco <stevenfalco@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include <config.h>

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include <epan/dissectors/packet-udp.h>

#define MIN_LEN         28

/* Prototypes */
void proto_reg_handoff_pidp11(void);
void proto_register_pidp11(void);

// Initialize the protocol.
static int              proto_pidp11 = -1;

// Initialize registered fields.
static int              hf_pidp11_sequence_number = -1;
static int              hf_pidp11_direction = -1;
static int              hf_pidp11_rpc_version = -1;
static int              hf_pidp11_program_number = -1;
static int              hf_pidp11_blinken_version = -1;
static int              hf_pidp11_blinken_function = -1;

// Values of the fields.
static uint32_t         pidp11_sequence_number = -1;
static int              pidp11_direction = -1;
static int              pidp11_rpc_version = -1;
static int              pidp11_program_number = -1;
static int              pidp11_blinken_version = -1;
static int              pidp11_blinken_function = -1;

static expert_field     ei_pidp11_expert = EI_INIT;

struct pidp11_request_key {
    guint32 conversation;
    guint32 sequence_number;
};

struct pidp11_request_val {
    guint               req_num;
    guint               rep_num;

    uint32_t            pidp11_sequence_number;
    int                 pidp11_direction;
    int                 pidp11_rpc_version;
    int                 pidp11_program_number;
    int                 pidp11_blinken_version;
    int                 pidp11_blinken_function;
};

static wmem_map_t *pidp11_request_hash = NULL;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define pidp11_UDP_PORT 0
static guint udp_port_pref = pidp11_UDP_PORT;

// Initialize the subtree pointers.
static gint ett_pidp11 = -1;

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


void logit(const char *format, ...)
{
    va_list		ap;
    static FILE         *logfp = 0;

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

static gint
pidp11_equal(gconstpointer v, gconstpointer w)
{
    const struct pidp11_request_key *v1 = (const struct pidp11_request_key *)v;
    const struct pidp11_request_key *v2 = (const struct pidp11_request_key *)w;

    logit("pidp11_equal %08x vs %08x, %08x vs %08x", v1->conversation, v2->conversation, v1->sequence_number, v2->sequence_number);
    if((v1->conversation == v2->conversation) && (v1->sequence_number == v2->sequence_number)) {
        logit("pidp11_equal yes");
        return 1;
    }

    logit("pidp11_equal no");
    return 0;
}

static guint
pidp11_hash(gconstpointer v)
{
    const struct pidp11_request_key *key = (const struct pidp11_request_key *)v;
    guint val;

    val = key->conversation + key->sequence_number;
    logit("pidp11_hash %08x", val);

    return val;
}

/* Code to actually dissect the packets */
static int
dissect_pidp11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_item *expert_ti;
    proto_tree *pidp11_tree;

    conversation_t *conversation;
    struct pidp11_request_key request_key;
    struct pidp11_request_key *new_request_key;
    struct pidp11_request_val *request_val = NULL;

    guint       offset          = 0;
    int         len             = 0;
    char        buf[128];

    logit("dissect_pidp11");

    // HEURISTICS

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
    pidp11_sequence_number     = tvb_get_ntohl(tvb, 0x00);
    pidp11_direction           = tvb_get_ntohl(tvb, 0x04);
    pidp11_rpc_version         = tvb_get_ntohl(tvb, 0x08);
    pidp11_program_number      = tvb_get_ntohl(tvb, 0x0c);
    pidp11_blinken_version     = tvb_get_ntohl(tvb, 0x10);
    pidp11_blinken_function    = tvb_get_ntohl(tvb, 0x14);

    if(pidp11_direction == 0) {
        // To server.
        if(pidp11_rpc_version != 2) {
            // reject
            return 0;
        }

        if(pidp11_program_number != 99) {
            // reject
            return 0;
        }

        if(pidp11_blinken_version != 1) {
            // reject
            return 0;
        }

        if((pidp11_blinken_function >= 1) && (pidp11_blinken_function <= 5)) {
            g_snprintf(buf, 128, "Client %s", low_funcs[pidp11_blinken_function - 1]);
        } else if((pidp11_blinken_function >= 100) && (pidp11_blinken_function <= 101)) {
            g_snprintf(buf, 128, "Client %s", mid_funcs[pidp11_blinken_function - 100]);
        } else if((pidp11_blinken_function >= 1000) && (pidp11_blinken_function <= 1001)) {
            g_snprintf(buf, 128, "Client %s", high_funcs[pidp11_blinken_function - 1000]);
        } else {
            // reject
            return 0;
        }
    } else if(pidp11_direction == 1) {
        // To client.
        if(pidp11_rpc_version != 0) {
            // reject
            return 0;
        }

        if(pidp11_program_number != 0) {
            // reject
            return 0;
        }

        if(pidp11_blinken_version != 0) {
            // reject
            return 0;
        }

        if(pidp11_blinken_function != 0) {
            // reject
            return 0;
        }
    } else {
        // reject
        return 0;
    }

    conversation = find_or_create_conversation(pinfo);

    request_key.conversation = conversation->conv_index;
    request_key.sequence_number = pidp11_sequence_number;

    request_val = (struct pidp11_request_val *) wmem_map_lookup(pidp11_request_hash, &request_key);

    // Only allocate a new hash element when it's a call to the server.
    if(!pinfo->fd->visited) {
        logit("not visited yet");
        if(!request_val && (pidp11_direction == 0)) {
            logit("no val and dir == to server, inserting request %d", pinfo->num);
            new_request_key = wmem_new(wmem_file_scope(), struct pidp11_request_key);
            *new_request_key = request_key;

            request_val = wmem_new(wmem_file_scope(), struct pidp11_request_val);
            request_val->req_num                        = pinfo->num;
            request_val->rep_num                        = 0;
            request_val->pidp11_sequence_number         = pidp11_sequence_number;
            request_val->pidp11_direction               = pidp11_direction;
            request_val->pidp11_rpc_version             = pidp11_rpc_version;
            request_val->pidp11_program_number          = pidp11_program_number;
            request_val->pidp11_blinken_version         = pidp11_blinken_version;
            request_val->pidp11_blinken_function        = pidp11_blinken_function;

            wmem_map_insert(pidp11_request_hash, new_request_key, request_val);
        }

        if(request_val && (pidp11_direction == 1)) {
            logit("val exists and dir == to client, inserting reply %d", pinfo->num);
            request_val->rep_num = pinfo->num;
        }
    }

    if(request_val && (pidp11_direction == 1)) {
        logit("val exists, our seq=0x%08x, hashed seq=0x%08x", pidp11_sequence_number, request_val->pidp11_sequence_number);
        if((request_val->pidp11_blinken_function >= 1) && (request_val->pidp11_blinken_function <= 5)) {
            g_snprintf(buf, 128, "Server %s", low_funcs[request_val->pidp11_blinken_function - 1]);
        } else if((request_val->pidp11_blinken_function >= 100) && (request_val->pidp11_blinken_function <= 101)) {
            g_snprintf(buf, 128, "Server %s", mid_funcs[request_val->pidp11_blinken_function - 100]);
        } else if((request_val->pidp11_blinken_function >= 1000) && (request_val->pidp11_blinken_function <= 1001)) {
            g_snprintf(buf, 128, "Server %s", high_funcs[request_val->pidp11_blinken_function - 1000]);
        } else {
            g_snprintf(buf, 128, "Server not matched");
        }
    }

    /*** COLUMN DATA ***/

    /* Set the Protocol column to the constant string of pidp11 */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "pidp11");

    col_set_str(pinfo->cinfo, COL_INFO, buf);

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    logit("dissect_pidp11 adding subtree");
    ti = proto_tree_add_item(tree, proto_pidp11, tvb, 0, -1, ENC_NA);
    logit("dissect_pidp11 added subtree");

    pidp11_tree = proto_item_add_subtree(ti, ett_pidp11);

    len = 4;
    expert_ti = proto_tree_add_item(pidp11_tree, hf_pidp11_sequence_number, tvb, offset, len, ENC_LITTLE_ENDIAN);
    offset += len;

    len = 4;
    expert_ti = proto_tree_add_item(pidp11_tree, hf_pidp11_direction, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    expert_ti = proto_tree_add_item(pidp11_tree, hf_pidp11_rpc_version, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    expert_ti = proto_tree_add_item(pidp11_tree, hf_pidp11_program_number, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    expert_ti = proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_version, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    expert_ti = proto_tree_add_item(pidp11_tree, hf_pidp11_blinken_function, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
    if ( 0 ) {
        expert_add_info(pinfo, expert_ti, &ei_pidp11_expert);
    }

    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

static const value_string RPC_direction[] = {
    { 0, "To Panel"},
    { 1, "To SIMH"},
    { 0, NULL }
};

static const value_string blinken_function[] = {
    { 1,    "RPC_BLINKENLIGHT_API_GETINFO"},
    { 2,    "RPC_BLINKENLIGHT_API_GETPANELINFO"},
    { 3,    "RPC_BLINKENLIGHT_API_GETCONTROLINFO"},
    { 4,    "RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES"},
    { 5,    "RPC_BLINKENLIGHT_API_SETPANEL_CONTROLVALUES"},
    { 100,  "RPC_PARAM_GET"},
    { 101,  "RPC_PARAM_SET"},
    { 1000, "RPC_TEST_DATA_TO_SERVER"},
    { 1001, "RPC_TEST_DATA_FROM_SERVER"},
    { 0,    NULL }
};

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_pidp11(void)
{
    module_t        *pidp11_module;
    expert_module_t *expert_pidp11;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_pidp11_sequence_number,  { "Sequence Number",  "pidp11.seq_num",    FT_UINT32, BASE_HEX, NULL, 0, "NULL", HFILL } },
        { &hf_pidp11_direction,        { "Direction",        "pidp11.direction",  FT_UINT32, BASE_NONE, VALS(RPC_direction), 0, "NULL", HFILL } },
        { &hf_pidp11_rpc_version,      { "RPC Version",      "pidp11.rpc_vers",   FT_UINT32, BASE_DEC, NULL, 0, "NULL", HFILL } },
        { &hf_pidp11_program_number,   { "Program Number",   "pidp11.prog_num",   FT_UINT32, BASE_DEC, NULL, 0, "NULL", HFILL } },
        { &hf_pidp11_blinken_version,  { "Blinken Version",  "pidp11.blink_vers", FT_UINT32, BASE_DEC, NULL, 0, "NULL", HFILL } },
        { &hf_pidp11_blinken_function, { "Blinken Function", "pidp11.blink_func", FT_UINT32, BASE_NONE, VALS(blinken_function), 0, "NULL", HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_pidp11
    };

    logit("proto_register_pidp11");
    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_pidp11_expert, { "pidp11.expert", PI_PROTOCOL, PI_ERROR, "Illegal version", EXPFILL } }
    };

    /* Register the protocol name and description */
    proto_pidp11 = proto_register_protocol("PiDP-11", "PiDP-11", "pidp-11");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_pidp11, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_pidp11 = expert_register_protocol(proto_pidp11);
    expert_register_field_array(expert_pidp11, ei, array_length(ei));

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

    /* Register a simple example preference */
    prefs_register_bool_preference(pidp11_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &pref_hex);

    /* Register an example port preference */
    prefs_register_uint_preference(pidp11_module, "udp.port", "pidp11 UDP Port",
            " pidp11 UDP port if other than the default",
            10, &udp_port_pref);

    pidp11_request_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pidp11_hash, pidp11_equal);
}

/* Heuristics test */
static gboolean
test_pidp11(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    int l;

    logit("test_pidp11");
    l = tvb_reported_length(tvb);
    logit("replen %d", l);

#if 0
    for(int i = 0; i < l; i++) {
        logit("%d = %02x", i, tvb_get_guint8(tvb, i));
    }
#endif

    // Check that the packet is long enough for it to belong to us.  The
    // shortest has MIN_LEN bytes of data after the UDP header.
    if(tvb_reported_length(tvb) < MIN_LEN) {
        logit("replen %d too short", l);
        return FALSE;
    }

    /* Check that there's enough data present to run the heuristics. If there
     * isn't, reject the packet; it will probably be dissected as data and if
     * the user wants it dissected despite it being short they can use the
     * "Decode-As" functionality. If your heuristic needs to look very deep into
     * the packet you may not want to require *all* data to be present, but you
     * should ensure that the heuristic does not access beyond the captured
     * length of the packet regardless. */
    logit("caplen %d", tvb_captured_length(tvb));
    if(tvb_captured_length(tvb) < MIN_LEN) {
        logit("caplen %d too short", l);
        return FALSE;
    }

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    pidp11_sequence_number     = tvb_get_ntohl(tvb, 0x00);
    pidp11_direction           = tvb_get_ntohl(tvb, 0x04);
    pidp11_rpc_version         = tvb_get_ntohl(tvb, 0x08);
    pidp11_program_number      = tvb_get_ntohl(tvb, 0x0c);
    pidp11_blinken_version     = tvb_get_ntohl(tvb, 0x10);
    pidp11_blinken_function    = tvb_get_ntohl(tvb, 0x14);
    logit("seq %x", pidp11_sequence_number);
    logit("dir %d", pidp11_direction);
    logit("rpc %d", pidp11_rpc_version);
    logit("pn %d", pidp11_program_number);
    logit("bv %d", pidp11_blinken_version);
    logit("bf %d", pidp11_blinken_function);

    if(pidp11_direction == 0) {
        // To server.
        if(pidp11_rpc_version != 2) {
            // reject
            logit("to server but wrong rpc version");
            return FALSE;
        }

        if(pidp11_program_number != 99) {
            // reject
            logit("to server but wrong program");
            return FALSE;
        }

        if(pidp11_blinken_version != 1) {
            // reject
            logit("to server but wrong blinken version");
            return FALSE;
        }

        if((pidp11_blinken_function >= 1) && (pidp11_blinken_function <= 5)) {
            ;
        } else if((pidp11_blinken_function >= 100) && (pidp11_blinken_function <= 101)) {
            ;
        } else if((pidp11_blinken_function >= 1000) && (pidp11_blinken_function <= 1001)) {
            ;
        } else {
            // reject
            logit("to server but illegal function %d", pidp11_blinken_function);
            return FALSE;
        }
        logit("good packet to server");
    } else if(pidp11_direction == 1) {
        // To client.
        if(pidp11_rpc_version != 0) {
            // reject
            logit("to client but bad rpc version");
            return FALSE;
        }

        if(pidp11_program_number != 0) {
            // reject
            logit("to client but bad program number");
            return FALSE;
        }

        if(pidp11_blinken_version != 0) {
            // reject
            logit("to client but bad blinken version");
            return FALSE;
        }

        if(pidp11_blinken_function != 0) {
            // reject
            logit("to client but bad blinken function");
            return FALSE;
        }

        logit("good packet to client");
    } else {
        // reject
        logit("bad packet direction");
        return FALSE;
    }

    return TRUE;
}

static guint
get_pidp11_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    logit("get_pidp11_len");
    return (guint) tvb_get_ntohs(tvb, offset+3);
}

static gboolean
dissect_pidp11_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    logit("dissect_pidp11_heur_udp");
    return (udp_dissect_pdus(tvb, pinfo, tree, 5, test_pidp11,
                     get_pidp11_len, dissect_pidp11, data) != 0);
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

    logit("proto_reg_handoff_pidp11");
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

    heur_dissector_add("udp", dissect_pidp11_heur_udp, "pidp11 over UDP",
                       "pidp11_udp", proto_pidp11, HEURISTIC_ENABLE);

    //dissector_add_uint("udp.port", current_port, pidp11_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
