#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
enum mdns_record_type {
    MDNS_RECORDTYPE_IGNORE = 0,
    // Address
    MDNS_RECORDTYPE_A = 1,
    // Domain Name pointer
    MDNS_RECORDTYPE_PTR = 12,
    // Arbitrary text string
    MDNS_RECORDTYPE_TXT = 16,
    // IP6 Address [Thomson]
    MDNS_RECORDTYPE_AAAA = 28,
    // Server Selection [RFC2782]
    MDNS_RECORDTYPE_SRV = 33,
    // Any available records
    MDNS_RECORDTYPE_ANY = 255
};

enum mdns_entry_type {
    MDNS_ENTRYTYPE_QUESTION = 0,
    MDNS_ENTRYTYPE_ANSWER = 1,
    MDNS_ENTRYTYPE_AUTHORITY = 2,
    MDNS_ENTRYTYPE_ADDITIONAL = 3
};

enum mdns_class { MDNS_CLASS_IN = 1, MDNS_CLASS_ANY = 255 };

typedef enum mdns_record_type mdns_record_type_t;
typedef enum mdns_entry_type mdns_entry_type_t;
typedef enum mdns_class mdns_class_t;
typedef struct mdns_string_t mdns_string_t;
typedef struct mdns_string_pair_t mdns_string_pair_t;
typedef struct mdns_string_table_item_t mdns_string_table_item_t;
typedef struct mdns_string_table_t mdns_string_table_t;
typedef struct mdns_record_t mdns_record_t;
typedef struct mdns_record_srv_t mdns_record_srv_t;
typedef struct mdns_record_ptr_t mdns_record_ptr_t;
typedef struct mdns_record_a_t mdns_record_a_t;
typedef struct mdns_record_aaaa_t mdns_record_aaaa_t;
typedef struct mdns_record_txt_t mdns_record_txt_t;



typedef int (*mdns_record_callback_fn)(int sock, const struct sockaddr* from, size_t addrlen,
                                       mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
                                       uint16_t rclass, uint32_t ttl, const void* data, size_t size,
                                       size_t name_offset, size_t name_length, size_t record_offset,
                                       size_t record_length, void* user_data);

// mDNS/DNS-SD public API

//! Open and setup a IPv4 socket for mDNS/DNS-SD. To bind the socket to a specific interface, pass
//! in the appropriate socket address in saddr, otherwise pass a null pointer for INADDR_ANY. To
//! send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
//! random user level ephemeral port. To run discovery service listening for incoming discoveries
//! and queries, you must set MDNS_PORT as port.
static int
mdns_socket_open_ipv4(const struct sockaddr_in* saddr);

//! Setup an already opened IPv4 socket for mDNS/DNS-SD. To bind the socket to a specific interface,
//! pass in the appropriate socket address in saddr, otherwise pass a null pointer for INADDR_ANY.
//! To send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
//! random user level ephemeral port. To run discovery service listening for incoming discoveries
//! and queries, you must set MDNS_PORT as port.
static int
mdns_socket_setup_ipv4(int sock, const struct sockaddr_in* saddr);

//! Open and setup a IPv6 socket for mDNS/DNS-SD. To bind the socket to a specific interface, pass
//! in the appropriate socket address in saddr, otherwise pass a null pointer for in6addr_any. To
//! send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
//! random user level ephemeral port. To run discovery service listening for incoming discoveries
//! and queries, you must set MDNS_PORT as port.
static int
mdns_socket_open_ipv6(const struct sockaddr_in6* saddr);

//! Setup an already opened IPv6 socket for mDNS/DNS-SD. To bind the socket to a specific interface,
//! pass in the appropriate socket address in saddr, otherwise pass a null pointer for in6addr_any.
//! To send one-shot discovery requests and queries pass a null pointer or set 0 as port to assign a
//! random user level ephemeral port. To run discovery service listening for incoming discoveries
//! and queries, you must set MDNS_PORT as port.
static int
mdns_socket_setup_ipv6(int sock, const struct sockaddr_in6* saddr);

//! Close a socket opened with mdns_socket_open_ipv4 and mdns_socket_open_ipv6.
static void
mdns_socket_close(int sock);

//! Listen for incoming multicast DNS-SD and mDNS query requests. The socket should have been opened
//! on port MDNS_PORT using one of the mdns open or setup socket functions. Buffer must be 32 bit
//! aligned. Parsing is stopped when callback function returns non-zero. Returns the number of
//! queries parsed.
static size_t
mdns_socket_listen(int sock, void* buffer, size_t capacity, mdns_record_callback_fn callback,
                   void* user_data);

//! Send a multicast DNS-SD reqeuest on the given socket to discover available services. Returns 0
//! on success, or <0 if error.
static int
mdns_discovery_send(int sock);

//! Recieve unicast responses to a DNS-SD sent with mdns_discovery_send. Any data will be piped to
//! the given callback for parsing. Buffer must be 32 bit aligned. Parsing is stopped when callback
//! function returns non-zero. Returns the number of responses parsed.
static size_t
mdns_discovery_recv(int sock, void* buffer, size_t capacity, mdns_record_callback_fn callback,
                    void* user_data);

//! Send a multicast mDNS query on the given socket for the given service name. The supplied buffer
//! will be used to build the query packet and must be 32 bit aligned. The query ID can be set to
//! non-zero to filter responses, however the RFC states that the query ID SHOULD be set to 0 for
//! multicast queries. The query will request a unicast response if the socket is bound to an
//! ephemeral port, or a multicast response if the socket is bound to mDNS port 5353. Returns the
//! used query ID, or <0 if error.
static int
mdns_query_send(int sock, mdns_record_type_t type, const char* name, size_t length, void* buffer,
                size_t capacity, uint16_t query_id);

//! Receive unicast responses to a mDNS query sent with mdns_discovery_recv, optionally filtering
//! out any responses not matching the given query ID. Set the query ID to 0 to parse all responses,
//! even if it is not matching the query ID set in a specific query. Any data will be piped to the
//! given callback for parsing. Buffer must be 32 bit aligned. Parsing is stopped when callback
//! function returns non-zero. Returns the number of responses parsed.
static size_t
mdns_query_recv(int sock, void* buffer, size_t capacity, mdns_record_callback_fn callback,
                void* user_data, int query_id);

//! Send a variable unicast mDNS query answer to any question with variable number of records to the
//! given address. Use the top bit of the query class field (MDNS_UNICAST_RESPONSE) in the query
//! recieved to determine if the answer should be sent unicast (bit set) or multicast (bit not set).
//! Buffer must be 32 bit aligned. The record type and name should match the data from the query
//! recieved. Returns 0 if success, or <0 if error.
static int
mdns_query_answer_unicast(int sock, const void* address, size_t address_size, void* buffer,
                          size_t capacity, uint16_t query_id, mdns_record_type_t record_type,
                          const char* name, size_t name_length, mdns_record_t answer,
                          mdns_record_t* authority, size_t authority_count,
                          mdns_record_t* additional, size_t additional_count);

//! Send a variable multicast mDNS query answer to any question with variable number of records. Use
//! the top bit of the query class field (MDNS_UNICAST_RESPONSE) in the query recieved to determine
//! if the answer should be sent unicast (bit set) or multicast (bit not set). Buffer must be 32 bit
//! aligned. Returns 0 if success, or <0 if error.
static int
mdns_query_answer_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                            mdns_record_t* authority, size_t authority_count,
                            mdns_record_t* additional, size_t additional_count);

//! Send a variable multicast mDNS announcement (as an unsolicited answer) with variable number of
//! records.Buffer must be 32 bit aligned. Returns 0 if success, or <0 if error. Use this on service
//! startup to announce your instance to the local network.
static int
mdns_announce_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                        mdns_record_t* authority, size_t authority_count, mdns_record_t* additional,
                        size_t additional_count);

//! Send a variable multicast mDNS announcement. Use this on service end for removing the resource
//! from the local network. The records must be identical to the according announcement.
static int
mdns_goodbye_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                       mdns_record_t* authority, size_t authority_count, mdns_record_t* additional,
                       size_t additional_count);

// Parse records functions

//! Parse a PTR record, returns the name in the record
static mdns_string_t
mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity);

//! Parse a SRV record, returns the priority, weight, port and name in the record
static mdns_record_srv_t
mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity);

//! Parse an A record, returns the IPv4 address in the record
static struct sockaddr_in*
mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length,
                    struct sockaddr_in* addr);

//! Parse an AAAA record, returns the IPv6 address in the record
static struct sockaddr_in6*
mdns_record_parse_aaaa(const void* buffer, size_t size, size_t offset, size_t length,
                       struct sockaddr_in6* addr);

//! Parse a TXT record, returns the number of key=value records parsed and stores the key-value
//! pairs in the supplied buffer
static size_t
mdns_record_parse_txt(const void* buffer, size_t size, size_t offset, size_t length,
                      mdns_record_txt_t* records, size_t capacity);

#ifdef __cplusplus
} // extern "C"
#endif
