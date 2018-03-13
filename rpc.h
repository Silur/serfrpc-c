#ifndef __SERF_RPC_H
#define __SERF_RPC_H
#include <stdlib.h>
#include <msgpack.h>

int sockfd, portno, n;
struct sockaddr_in serv_addr;
struct hostent *server;

int RPC_init(char *host, int port);
void serf_handshake(int version);
void serf_auth(char *key);
void serf_event(char *name, char *payload, unsigned char coalesce);
void serf_force_leave(char *name);
size_t serf_join(char **names, size_t size, unsigned char replay);
char *serf_members();
char *serf_members_filtered(char *name, unsigned char *addr, unsigned short port, char *status, int count, ...);
void serf_tags(char ***keys, int taglen, char **delete_tags, int dtaglen);
void serf_stream(char *type, void (*cb)(msgpack_unpacked r));
void serf_monitor(char *loglevel);
void serf_stop(int seq);
void serf_leave();
void serf_query(char *name, char *payload, int timeout, int ack, char ***tags, int tlen, char **nodes, int nlen, void (*cb)(msgpack_unpacked r));
void serf_respond(int id, char *payload);
int serf_install_key(char *key);
int serf_use_key(char *key);
int serf_remove_key(char *key);
char **serf_list_keys();
int serf_get_coordinate(char *node, float *adjustment, float *error, float *height, float **vec);
#endif
