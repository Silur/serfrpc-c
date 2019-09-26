#include <msgpack.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <stdarg.h>
#include "rpc.h"

#define READ_CHUNK_SIZE 512

#define command(name) \
	msgpack_sbuffer hbuf;\
	msgpack_sbuffer bbuf;\
	msgpack_packer pk;\
	signed int seq_time = time(0);\
	msgpack_sbuffer_init(&hbuf);\
	msgpack_packer_init(&pk, &hbuf, msgpack_sbuffer_write);\
	msgpack_pack_map(&pk, 2);\
	msgpack_pack_str(&pk, 7);\
	msgpack_pack_str_body(&pk, "Command", 7);\
	msgpack_pack_str(&pk, strlen(name));\
	msgpack_pack_str_body(&pk, name, strlen(name));\
	msgpack_pack_str(&pk, 3);\
	msgpack_pack_str_body(&pk, "Seq", 3);\
	msgpack_pack_int(&pk, seq_time);\
	msgpack_sbuffer_init(&bbuf);\
	msgpack_packer_init(&pk, &bbuf, msgpack_sbuffer_write);

#define exec_rpc(ret) {\
	size_t len = hbuf.size + bbuf.size;\
	char *buf = malloc(len);\
	memcpy(buf, hbuf.data, hbuf.size);\
	memcpy(buf + hbuf.size, bbuf.data, bbuf.size);\
	rpc_call(buf, len, ret);\
	free(buf);\
}

char*
extract_string_from_map(msgpack_object *obj, const char* key)
{
	if(obj->type != MSGPACK_OBJECT_MAP)
	{
		return 0;
	}

	for (unsigned int ii = 0; ii < obj->via.map.size; ++ii)
	{
		msgpack_object currentKey = obj->via.map.ptr[ii].key;
		msgpack_object currentVal = obj->via.map.ptr[ii].val;

		assert(currentKey.type == MSGPACK_OBJECT_STR);

		if (strncmp(currentKey.via.str.ptr, key, currentKey.via.str.size) == 0)
		{
			char* result = (char*) malloc(currentVal.via.str.size + 1);
			strncpy(result, currentVal.via.str.ptr, currentVal.via.str.size);
			result[currentVal.via.str.size] = 0;
			return result;
		}
	}

	return 0;
}

int
handle_response(char *response, size_t response_len, msgpack_unpacked *ret)
{
	// deserialize header
	msgpack_unpacked header;
	size_t offset = 0;

	msgpack_unpacked_init(&header);

	if (msgpack_unpack_next(&header, response, response_len, &offset) != MSGPACK_UNPACK_SUCCESS)
	{
		fprintf(stderr, "Unable to deserialize response header\n");
		return 1;
	}

	// validate header
	msgpack_object header_obj = header.data;

	char* error = extract_string_from_map(&header_obj, "Error");

	if (error == 0)
	{
		fprintf(stderr, "Unexpected response header format\n");
		msgpack_object_print(stderr, header_obj);
		fprintf(stderr, "\n");
		free(error);
		return 1;
	}

	if (strlen(error) > 0)
	{
		fprintf(stderr, "RPC returned error: %s\n", error);
		free(error);
		return 1;
	}

	free(error);

	// parse body
	if (ret != 0)
	{
		msgpack_unpacked_init(ret);

		if (msgpack_unpack_next(ret, response, response_len, &offset) != MSGPACK_UNPACK_SUCCESS)
		{
			fprintf(stderr, "Unable to deserialize response body\n");
            return 1;
		}
	}

	return 0;
}

static size_t
rpc_call(char *buf, size_t len, msgpack_unpacked *ret)
{
	// send request
	ssize_t bytes_written = write(sockfd, buf, len);
	if(bytes_written < 0)
	{
		perror("RPC write error");
		return 0;
	}

	// receive response
	ssize_t bytes_read = 0;
	ssize_t chunk_size = 0;
	char *response = 0;
	char *temp;

	while (1)
	{
		temp = realloc(response, bytes_read + READ_CHUNK_SIZE);
		if(!temp)
		{
			perror("memory allocation error");
			return 0;
		}
		response = temp;

		chunk_size = read(sockfd, response + bytes_read, READ_CHUNK_SIZE);

		if(chunk_size < 0)
		{
			perror("RPC read error");
			free(response);
			return 0;
		}

		bytes_read += chunk_size;

		if(chunk_size < READ_CHUNK_SIZE) break;
	}

	// handle response
	int resp_error = handle_response(response, bytes_read, ret);
	free(response);
	return resp_error ? 0 : bytes_read;
}

int
RPC_init(char *host, int port)
{
	portno = port;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{ 
		perror("ERROR opening socket");
		return -1;
	}
	server = gethostbyname(host);
	if (server == 0) 
	{
		fprintf(stderr,"ERROR, no such host\n");
		return -1;
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
			(char *)&serv_addr.sin_addr.s_addr,
			server->h_length);
	serv_addr.sin_port = htons(portno);

	if(connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("RPC connection error");
		return -1;
	}

	return 1;
}

void
serf_handshake(int version)
{
	command("handshake");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 7);
	msgpack_pack_str_body(&pk, "Version", 7);
	msgpack_pack_int(&pk, version);
	exec_rpc(0);
}

void
serf_auth(char *key)
{
	command("auth");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 7);
	msgpack_pack_str_body(&pk, "AuthKey", 7);
	size_t len = strlen(key);
	msgpack_pack_str(&pk, len);
	msgpack_pack_str_body(&pk, key, len);
	exec_rpc(0);
}

void
serf_event(char *name, char *payload, unsigned char coalesce)
{
	size_t name_len = strlen(name);
	size_t payload_len = strlen(payload);
	command("event");
	msgpack_pack_map(&pk, 3);
	msgpack_pack_str(&pk, 4);
	msgpack_pack_str_body(&pk, "Name", 4);
	msgpack_pack_str(&pk, name_len);
	msgpack_pack_str_body(&pk, name, name_len);

	msgpack_pack_str(&pk, 7);
	msgpack_pack_str_body(&pk, "Payload", 7);
	msgpack_pack_str(&pk, payload_len);
	msgpack_pack_str_body(&pk, payload, payload_len);

	msgpack_pack_str(&pk, 8);
	msgpack_pack_str_body(&pk, "Coalesce", 8);
	coalesce == 1 ? msgpack_pack_true(&pk) : msgpack_pack_false(&pk);
	exec_rpc(0);
}

void
serf_force_leave(char *name)
{
	size_t name_len = strlen(name);
	command("force-leave");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 4);
	msgpack_pack_str_body(&pk, "Name", 4);
	msgpack_pack_str(&pk, name_len);
	msgpack_pack_str_body(&pk, name, name_len);
	exec_rpc(0);
}

size_t
serf_join(char **names, size_t size, unsigned char replay)
{
	size_t curr_nlen;
	size_t i;
	command("join");
	msgpack_pack_map(&pk, 2);
	msgpack_pack_str(&pk, 8);
	msgpack_pack_str_body(&pk, "Existing", 8);
	msgpack_pack_array(&pk, size);
	for(i=0; i<size; i++)
	{
		curr_nlen = strlen(names[i]);
		msgpack_pack_str(&pk, curr_nlen);
		msgpack_pack_str_body(&pk, names[i], curr_nlen);
	}
	msgpack_pack_str(&pk, 6);
	msgpack_pack_str_body(&pk, "Replay", 6);
	replay == 1 ? msgpack_pack_true(&pk) : msgpack_pack_false(&pk);
	
	msgpack_unpacked reply;
	exec_rpc(&reply);
	
	msgpack_object root = reply.data;
	if(root.type != MSGPACK_OBJECT_MAP)	goto rpcerr;

	msgpack_object num = root.via.map.ptr->val;
	if(num.type != MSGPACK_OBJECT_POSITIVE_INTEGER) goto rpcerr;

	return num.via.u64;

rpcerr:
		fprintf(stderr, "Invalid RPC response: ");
		msgpack_object_print(stderr, root);
		return -1;

}

char
*serf_members()
{
	command("members");
	msgpack_unpacked reply;
	exec_rpc(&reply);
	msgpack_object root = reply.data;
	if(root.type != MSGPACK_OBJECT_MAP)	goto rpcerr;

	msgpack_object arr = root.via.map.ptr->val;
	if(arr.type != MSGPACK_OBJECT_ARRAY) goto rpcerr;

	char *ret = malloc(arr.via.array.size*512);
	msgpack_object_print_buffer(ret, arr.via.array.size*512, arr);
	return ret;
rpcerr:
		fprintf(stderr, "Invalid RPC response: ");
		msgpack_object_print(stderr, root);
		return 0;
}

char*
serf_members_filtered(char *name, unsigned char *addr, unsigned short port, char *status, int count, ...)
{
	va_list ap;
	int i;
	int pcount = 0;
	command("members-filtered");
	msgpack_unpacked reply;
	if(name) pcount++;
	if(addr) pcount++;
	if(port) pcount++;
	if(status) pcount++;
	if(count>0) pcount++;
	msgpack_pack_map(&pk, pcount);
	if(name)
	{
		msgpack_pack_str(&pk, 4);
		msgpack_pack_str_body(&pk, "Name", 4);
		msgpack_pack_str(&pk, strlen(name));
		msgpack_pack_str_body(&pk, name, strlen(name));
	}
	if(addr)
	{
		msgpack_pack_str(&pk, 4);
		msgpack_pack_str_body(&pk, "Addr", 4);
		msgpack_pack_array(&pk, 4);
		// unrolling works for 4 here
		msgpack_pack_uint8(&pk, addr[0]);
		msgpack_pack_uint8(&pk, addr[1]);
		msgpack_pack_uint8(&pk, addr[2]);
		msgpack_pack_uint8(&pk, addr[3]);
	}
	if(port)
	{
		msgpack_pack_str(&pk, 4);
		msgpack_pack_str_body(&pk, "Port", 4);
		msgpack_pack_uint16(&pk, port);
	}
	if(status)
	{
		msgpack_pack_str(&pk, 6);
		msgpack_pack_str_body(&pk, "Status", 6);
		msgpack_pack_str(&pk, strlen(status));
		msgpack_pack_str_body(&pk, status, strlen(status));
	}
	if(count > 0)
	{
		char *key;
		char *value;
		char *c;
		va_start(ap, count);
		msgpack_pack_str(&pk, 4);
		msgpack_pack_str_body(&pk, "Tags", 4);
		msgpack_pack_map(&pk, count);
		for(i=0; i<count; i++)
		{
			c = va_arg(ap, char*);
			key = strtok(c, ":");
			value = strtok(0, ":");
			msgpack_pack_str(&pk, strlen(key));
			msgpack_pack_str_body(&pk, key, strlen(key));
			msgpack_pack_str(&pk, strlen(value));
			msgpack_pack_str_body(&pk, value, strlen(value));
		}
	}

	exec_rpc(&reply);
	msgpack_object root = reply.data;
	if(root.type != MSGPACK_OBJECT_MAP)	goto rpcerr;

	msgpack_object arr = root.via.map.ptr->val;
	if(arr.type != MSGPACK_OBJECT_ARRAY) goto rpcerr;

	char *ret = malloc(arr.via.array.size*512);
	msgpack_object_print_buffer(ret, arr.via.array.size*512, arr);
	return ret;
rpcerr:
		fprintf(stderr, "Invalid RPC response: ");
		msgpack_object_print(stderr, root);
		return 0;
}

void 
serf_tags(char ***tags, int taglen, char **delete_tags, int dtaglen)
{
	int i;
	int ht = taglen > 0;
	int hd = dtaglen > 0;
	if(!ht && !hd) return;
	command("tags");
	msgpack_pack_map(&pk, ht+hd);
	if(ht) 
	{
		msgpack_pack_str(&pk, 4);
		msgpack_pack_str_body(&pk, "Tags", 4);
		msgpack_pack_map(&pk, taglen);
		for (i=0; i<taglen; i++)
		{
			msgpack_pack_str(&pk, strlen(tags[i][0]));
			msgpack_pack_str_body(&pk, tags[i][0], strlen(tags[i][0]));
			msgpack_pack_str(&pk, strlen(tags[i][1]));
			msgpack_pack_str_body(&pk, tags[i][1], strlen(tags[i][1]));
		}
	}
	if(hd) 
	{
		msgpack_pack_str(&pk, 10);
		msgpack_pack_str_body(&pk, "DeleteTags", 10);
		msgpack_pack_array(&pk, dtaglen);
		for (i=0; i<dtaglen; i++)
		{
			msgpack_pack_str(&pk, strlen(delete_tags[i]));
			msgpack_pack_str_body(&pk, delete_tags[i], strlen(delete_tags[i]));
		}
	}
	exec_rpc(0);
}

void
serf_stream(char *type, void (*cb)(msgpack_unpacked r))
{
	command("stream");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 4);
	msgpack_pack_str_body(&pk, "Type", 4);
	msgpack_pack_str(&pk, strlen(type));
	msgpack_pack_str_body(&pk, type, strlen(type));
	
	msgpack_unpacked reply;
	exec_rpc(&reply);
	cb(reply);
}

void
serf_monitor(char *loglevel)
{
	command("monitor");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 8);
	msgpack_pack_str_body(&pk, "LogLevel", 8);
	msgpack_pack_str(&pk, strlen(loglevel));
	msgpack_pack_str_body(&pk, loglevel, strlen(loglevel));
	exec_rpc(0);
}

void
serf_stop(int seq)
{
	command("stop");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 4);
	msgpack_pack_str_body(&pk, "Stop", 4);
	msgpack_pack_int(&pk, seq);
	exec_rpc(0);
}

void
serf_leave()
{
	command("leave");
	exec_rpc(0);
}

void
serf_query(char *name, char *payload, int timeout, int ack, char ***tags, int tlen, char **nodes, int nlen, void (*cb)(msgpack_unpacked r))
{
	command("query");
	msgpack_pack_map(&pk, 4+(tlen>0)+(nlen>0));
	msgpack_pack_str(&pk, 4);
	msgpack_pack_str_body(&pk, "Name", 4);
	msgpack_pack_str(&pk, strlen(name));
	msgpack_pack_str_body(&pk, name, strlen(name));
	msgpack_pack_str(&pk, 7);
	msgpack_pack_str_body(&pk, "Payload", 7);
	msgpack_pack_str(&pk, strlen(payload));
	msgpack_pack_str_body(&pk, payload, strlen(payload));
	msgpack_pack_str(&pk, 7);
	msgpack_pack_str_body(&pk, "Timeout", 7);
	msgpack_pack_int(&pk, timeout);
	msgpack_pack_str(&pk, 10);
	msgpack_pack_str_body(&pk, "RequestAck", 10);
	ack > 0 ? msgpack_pack_true(&pk) : msgpack_pack_false(&pk);
	if (tlen > 0)
	{
		msgpack_pack_str(&pk, 10);
		msgpack_pack_str_body(&pk, "FilterTags", 10);
		msgpack_pack_map(&pk, tlen);
		int i;
		for(i=0; i<tlen; i++)
		{
			msgpack_pack_str(&pk, strlen(tags[i][0]));
			msgpack_pack_str_body(&pk, tags[i][0], strlen(tags[i][0]));
			msgpack_pack_str(&pk, strlen(tags[i][1]));
			msgpack_pack_str_body(&pk, tags[i][1], strlen(tags[i][1]));
		}
	}
	if(nlen > 0)
	{
		msgpack_pack_str(&pk, 11);
		msgpack_pack_str_body(&pk, "FilterNodes", 11);
		msgpack_pack_array(&pk, nlen);
		int i;
		for(i=0; i<nlen; i++)
		{
			msgpack_pack_str(&pk, strlen(nodes[i]));
			msgpack_pack_str_body(&pk, nodes[i], strlen(nodes[i]));
		}
	}
	msgpack_unpacked reply;
	exec_rpc(&reply);
	cb(reply);
}

void
serf_respond(int id, char *payload)
{
	command("respond");
	msgpack_pack_map(&pk, 2);
	msgpack_pack_str(&pk, 2);
	msgpack_pack_str_body(&pk, "ID", 2);
	msgpack_pack_int(&pk, id);
	msgpack_pack_str(&pk, 7);
	msgpack_pack_str_body(&pk, "Payload", 7);
	msgpack_pack_str(&pk, strlen(payload));
	msgpack_pack_str_body(&pk, payload, strlen(payload));
	exec_rpc(0);
}

int
serf_install_key(char *key)
{
	command("install-key");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 3);
	msgpack_pack_str_body(&pk, "Key", 3);
	msgpack_pack_str(&pk, strlen(key));
	msgpack_pack_str_body(&pk, key, strlen(key));
	msgpack_unpacked reply;
	exec_rpc(&reply);

	msgpack_object root = reply.data;
	if(root.type != MSGPACK_OBJECT_MAP)	goto rpcerr;

	msgpack_object num = root.via.map.ptr[1].val;
	if(num.type != MSGPACK_OBJECT_POSITIVE_INTEGER) goto rpcerr;

	return num.via.u64 == 0;
rpcerr:
		fprintf(stderr, "Invalid RPC response: ");
		msgpack_object_print(stderr, root);
		return -1;
}

int
serf_use_key(char *key)
{
	return serf_install_key(key); // same req and response body
}

int
serf_remove_key(char *key)
{
	return serf_install_key(key); // same req and response body
}

char **
serf_list_keys()
{
	command("list-keys");
	msgpack_unpacked reply;
	exec_rpc(&reply);
	msgpack_object root = reply.data;
	if(root.type != MSGPACK_OBJECT_MAP)	goto rpcerr;

	msgpack_object keylist = root.via.map.ptr[1].val;
	if(keylist.type != MSGPACK_OBJECT_MAP) goto rpcerr;
	char **ret = malloc(keylist.via.map.size*24);
	unsigned int i;
	for(i=0; i<keylist.via.map.size; i++)
	{
		const char *ptr = keylist.via.map.ptr[i].val.via.str.ptr;
		ret[i] = malloc(strlen(ptr));
		strncpy(ret[i], ptr, strlen(ptr));
	}
	return ret;
rpcerr:
		fprintf(stderr, "Invalid RPC response: ");
		msgpack_object_print(stderr, root);
		return 0;
}

int
serf_get_coordinate(char *node, float *adjustment, float *error, float *height, float **vec)
{
	command("get-coordinate");
	msgpack_pack_map(&pk, 1);
	msgpack_pack_str(&pk, 4);
	msgpack_pack_str_body(&pk, "Node", 4);
	msgpack_pack_str(&pk, strlen(node));
	msgpack_pack_str_body(&pk, node, strlen(node));
	msgpack_unpacked reply;
	exec_rpc(&reply);
	msgpack_object root = reply.data;
	if(root.type != MSGPACK_OBJECT_MAP)	goto rpcerr;
	if(root.via.map.ptr[1].val.via.boolean == false) return 0;
	msgpack_object results = root.via.map.ptr[0].val;
	if(results.type != MSGPACK_OBJECT_MAP) goto rpcerr;
	*adjustment = results.via.map.ptr[0].val.via.f64;
	*error = results.via.map.ptr[1].val.via.f64;
	*height = results.via.map.ptr[2].val.via.f64;
	*vec = malloc(results.via.map.ptr[3].val.via.array.size*(sizeof(float*)));
	unsigned int i;
	for(i=0; i<results.via.map.ptr[3].val.via.array.size; i++)
	{
		*vec[i] = results.via.map.ptr[3].val.via.array.ptr[i].via.f64;
	}

rpcerr:
		fprintf(stderr, "Invalid RPC response: ");
		msgpack_object_print(stderr, root);
		return 0;
}
#undef command
#undef exec_rpc
