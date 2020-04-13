#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <stdint.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "ei.h"
#include "erl_driver.h"
#include "memory_mosq.h"
#include "putget.h"

#define DEBUG(FMT, ...) fprintf(stderr, FMT "\r\n", ##__VA_ARGS__)

#define event2sock(EV) ((int) ((long) (EV)))
#define sock2event(FD) ((ErlDrvEvent) ((long) (FD)))
#define DEFAULT_POLL_PERIOD 10

#include "mosquitto_broker_internal.h"

static int get_string(char *buf, ErlDrvSizeT len, int* index, char** s, ei_x_buff* x);
static void args_to_argv(char * args,  int* argc, char*** argv);

static void encode_ok(ei_x_buff* x);
static void encode_error(ei_x_buff* x);

static ErlDrvBinary* ei_x_to_new_binary(ei_x_buff* x);

#include "mosquitto_embed.h"

//----------------------------------
// Defines must be in sync with mosquitto_embed.ex
//----------------------------------
#define DRV_CMD_ECHO 0
#define DRV_CMD_INIT 1
#define DRV_CMD_POLL_PERIOD 2
#define DRV_CMD_OPEN_CLIENT 3
#define DRV_CMD_SUBSCRIBE 4
#define DRV_CMD_UNSUBSCRIBE 5
#define DRV_CMD_PUBLISH 6

struct mosquitto_embed_data_s;
typedef struct mosquitto_embed_data_s mosquitto_embed_data;

typedef struct {
  char* topic;
  ErlDrvTermData pid;
  ErlDrvTermData port;
  ErlDrvMonitor monitor;
  ei_x_buff user_data;
  mosquitto_embed_data * d;

  // Hash Lookup values
  UT_hash_handle hh_topic;
  UT_hash_handle hh_pid;
  UT_hash_handle hh_monitor;
} mosq_sub_t;

struct mosquitto_embed_data_s {
  ErlDrvPort  port;
  struct mosquitto_db *db;
  mosq_sock_t *listensock;
  int listensock_count;
  int poll_period;
  struct mosquitto * mosq_context;

  mosq_sub_t * subs_by_topic;
  mosq_sub_t * subs_by_monitor;
};

// This is needed for select_stop()
static struct mosquitto_db *db;

static ErlDrvData start(ErlDrvPort port, char *buff)
{
  //----------------------------------
  // Create the Erlang Driver Ptr
  //----------------------------------
  mosquitto_embed_data* d = (mosquitto_embed_data*)driver_alloc(sizeof(mosquitto_embed_data));
  memset(d, 0, sizeof(mosquitto_embed_data));

  d->port = port;
  set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);

  return (ErlDrvData)d;
}

static void stop(ErlDrvData handle)
{
  mosquitto_embed_data* d = (mosquitto_embed_data*)handle;

  for(int i=0; i < d->listensock_count; i++)
  {
    driver_select(d->port, sock2event(d->listensock[i]), ERL_DRV_READ,0);
  }
  mosquitto_deinit();
  driver_free((char*)handle);
}

static int cmd_echo(char *s, mosquitto_embed_data* data, ei_x_buff* x)
{
  // mosquitto_embed_data* d = (mosquitto_embed_data*)handle;
  driver_output(data->port, s, strlen(s));
  encode_ok(x);
  // encode_error(x, conn);
  return 0;
}

static int subscribe_callback(
  struct mosquitto_db *db, 
  struct mosquitto *context, 
  const char *topic, 
  struct mosquitto_msg_store *msg_store, 
  mosquitto_property *properties,
  mosq_user_context_t user_context)
{
  mosq_sub_t * mosq_sub = (mosq_sub_t *)user_context;
  DEBUG("subscribe_callback");
  DEBUG("%s %.*s %i", topic, msg_store->payloadlen, (char*)UHPA_ACCESS_PAYLOAD(msg_store), *(int*)user_context);

  void * payload = UHPA_ACCESS_PAYLOAD(msg_store);
  int payloadlen = msg_store->payloadlen;

  ErlDrvTermData spec[] = {
    ERL_DRV_BUF2BINARY, TERM_DATA(topic), TERM_DATA(strlen(topic)),
    ERL_DRV_BUF2BINARY, TERM_DATA(payload), TERM_DATA(payloadlen),
    ERL_DRV_EXT2TERM, TERM_DATA(mosq_sub->user_data.buff), TERM_DATA(mosq_sub->user_data.index),
    ERL_DRV_TUPLE, 3,
  };

  int spec_len = sizeof(spec)/sizeof(ErlDrvTermData);
  
  erl_drv_send_term(
    mosq_sub->port,
    mosq_sub->pid,
    spec,
    spec_len);

  return 0;
}

static int cmd_init(char *buf, ErlDrvSizeT len, int* index, mosquitto_embed_data* d, ei_x_buff* x)
{
  int argc;
  char **argv;
  char * args;

  DEBUG("init");

  if(get_string(buf, len, index, &args, x) < 0)
  {
    DEBUG("Unable to decode args");
    goto exit_on_error;
  }

  args_to_argv(args, &argc, &argv);
  driver_free(args);

  mosquitto_init(argc, argv);
  db = mosquitto__get_db();
  mosquitto__get_listensock(&(d->listensock), &(d->listensock_count));

  d->db = db;

  for(int i=0; i < d->listensock_count; i++)
  {
    driver_select(d->port, sock2event(d->listensock[i]), ERL_DRV_READ,1);
  }

  db->start_time = mosquitto_time();
#ifdef WITH_PERSISTENCE
  int_db->last_backup = mosquitto_time();
#endif
  d->poll_period = DEFAULT_POLL_PERIOD;
  driver_set_timer(d->port, d->poll_period);
  
  encode_ok(x);
  return 0;
  exit_on_error:
    encode_error(x);
    return 0;
}

static int cmd_open_client(char *buf, ErlDrvSizeT len, int* index, mosquitto_embed_data* d, ei_x_buff* x)
{
  char * client_name;
  if(get_string(buf, len, index, &client_name, x) < 0)
  {
    DEBUG("Unable to decode client_name");
    goto exit_on_error;
  }

  DEBUG("client_name %s", client_name);
  d->mosq_context = mosquitto_plugin__create_context(db, client_name);
  driver_free(client_name);

  if(d->mosq_context != NULL)
  {
    encode_ok(x);
  }
  else
  {
    encode_error(x);
  }
  
  return 0;
exit_on_error:
  return -1;
}

static int cmd_subscribe(char *buf, ErlDrvSizeT len, int* index, mosquitto_embed_data* d, ei_x_buff* x)
{
  int term_size;
  int term_type;
  int user_data_index;
  ErlDrvTermData caller_pid;
  DEBUG("cmd_subscribe");

  if (ei_decode_tuple_header(buf, index, &term_size) < 0)
  {
      ei_get_type(buf, index, &term_type, &term_size);
      DEBUG("Expecting {topic, user_data} tuple - got %i %c %i", term_type, term_type, term_size);
      encode_error(x);
      goto exit_on_error;
  }
  if (term_size != 2)
  {
      DEBUG("Expecting 2-tuple, got %i", term_size);
      encode_error(x);
      goto exit_on_error;
  }

  char *topic = NULL;
  if (get_string(buf, len, index, &topic, x) < 0)
  {
      DEBUG("Cannot decode Topic");
      encode_error(x);
      goto exit_on_error;
  }
  DEBUG("topic %s", topic);

  user_data_index = *index;

  if(ei_skip_term(buf, &user_data_index) < 0)
  {
      DEBUG("Cannot decode User Data");
      encode_error(x);
      goto exit_on_error;
  }
  DEBUG("driver_caller");
  caller_pid = driver_caller(d->port);

  mosq_sub_t * mosq_sub = driver_alloc(sizeof(mosq_sub_t));
  ei_x_new_with_version(&(mosq_sub->user_data));

  // Copy the user data over
  DEBUG("ei_x_append_buf");
  ei_x_append_buf(&(mosq_sub->user_data), &buf[*index], user_data_index-*index);

  mosq_sub->d = d;
  mosq_sub->topic = topic;
  mosq_sub->pid = caller_pid;
  mosq_sub->port = driver_mk_port(d->port);

  if(d->mosq_context != NULL)
  {
    mosq_sub_t * old_sub = NULL;
    // Remove any existing subscription for this topic
    HASH_FIND(hh_topic, d->subs_by_topic, topic, strlen(topic), old_sub);
    if(old_sub != NULL)
    {
      DEBUG("old_sub");
      mosquitto_plugin__unsubscribe(db, d->mosq_context, topic);
      HASH_DELETE(hh_topic, d->subs_by_topic, old_sub);
    }
    
    mosquitto_plugin__subscribe(db, d->mosq_context, topic, subscribe_callback, mosq_sub);
    HASH_ADD_KEYPTR(hh_topic, d->subs_by_topic, topic, strlen(topic), mosq_sub);
  }
  else
  {
    DEBUG("No Context");
  }
  if(topic != NULL)
  {
    driver_free(topic);
  }

  encode_ok(x);
  return 0;
exit_on_error:
  return -1;
}

static int cmd_unsubscribe(char *buf, ErlDrvSizeT len, int* index, mosquitto_embed_data* d, ei_x_buff* x)
{
  DEBUG("cmd_unsubscribe");

  char *topic = NULL;
  if (get_string(buf, len, index, &topic, x) < 0)
  {
      DEBUG("Cannot decode Topic");
      encode_error(x);
      goto exit_on_error;
  }
  DEBUG("topic %s", topic);

  mosq_sub_t * old_sub = NULL;
  // Remove any existing subscription for this topic
  HASH_FIND(hh_topic, d->subs_by_topic, topic, strlen(topic), old_sub);
  if(old_sub != NULL)
  {
    DEBUG("found %s", topic);
    mosquitto_plugin__unsubscribe(db, d->mosq_context, topic);
    HASH_DELETE(hh_topic, d->subs_by_topic, old_sub);
    encode_ok(x);
  }
  else
  {
    DEBUG("cannot find %s", topic);
    encode_error(x);
  }
  
  if(topic != NULL)
  {
    driver_free(topic);
  }

exit_on_error:  
  return 0;
}

static int cmd_publish(char *buf, ErlDrvSizeT len, int* index, mosquitto_embed_data* d, ei_x_buff* x)
{
  int term_size;
  int term_type;
  int user_data_index;
  ErlDrvTermData caller_pid;
  uint32_t message_expiry_interval = 0;

  long qos = 0;
  int retain = 0;
  mosquitto_property *msg_properties = NULL;

  DEBUG("cmd_publish");

  // Support the following tuples
  //   {topic, payload, retain, qos}
  //   {topic, payload, retain}
  //   {topic, payload}

  if (ei_decode_tuple_header(buf, index, &term_size) < 0)
  {
      ei_get_type(buf, index, &term_type, &term_size);
      DEBUG("Expecting {topic, payoad} tuple - got %i %c %i", term_type, term_type, term_size);
      encode_error(x);
      goto exit_on_error;
  }
  if (term_size < 2)
  {
      DEBUG("Expecting 2+-tuple, got %i", term_size);
      encode_error(x);
      goto exit_on_error;
  }

  char *topic = NULL;
  if (get_string(buf, len, index, &topic, x) < 0)
  {
      DEBUG("Cannot decode Topic");
      encode_error(x);
      goto exit_on_error;
  }
  DEBUG("topic %s", topic);

  // Manually decode the payload binary to avoid an extra memcpy
  const char *payload_ptr = buf + *index;
  ei_skip_term(buf, index);
  if (get8(payload_ptr) != ERL_BINARY_EXT)
  {
      DEBUG("Expecting payload as Binary");
      encode_error(x);
      goto exit_on_error;
  }

  uint32_t payloadlen = get32be(payload_ptr);
  // payload_ptr now points to the payload itself

  // retain
  if ( (term_size > 2) && (ei_decode_boolean(buf, index, &retain) < 0))
  {
      DEBUG("Cannot decode retain");
      encode_error(x);
      goto exit_on_error;
  }

  // qos
  if ( (term_size > 3) && (ei_decode_long(buf, index, &qos) < 0))
  {
      DEBUG("Cannot decode qos");
      encode_error(x);
      goto exit_on_error;
  }

  // mosquitto_property_add_string(&msg_properties, MQTT_PROP_CONTENT_TYPE, "application/json");

  if(d->mosq_context != NULL)
  {
    
    mosquitto_plugin__publish(
      d->db, 
      d->mosq_context,
      topic,
      qos,
      payloadlen,
      payload_ptr,
      retain,
      message_expiry_interval,
      msg_properties
      );
  }
  else
  {
    DEBUG("No Context");
  }
  if(topic != NULL)
  {
    driver_free(topic);
  }

  encode_ok(x);
  return 0;
exit_on_error:
  return -1;
}


static ErlDrvSSizeT call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen,
                 unsigned int *flags)
{
  int nlen = -1;
  int r = -1;
  ei_x_buff x;
  mosquitto_embed_data* data = (mosquitto_embed_data*)drv_data; 
  int index = 0;
  int ver;
  

  if(ei_decode_version(buf, &index, &ver) < 0)
  {
    DEBUG("cannot decode version");
  }
  else
  {
    DEBUG("Version %i", ver);
  }

  ei_x_new_with_version(&x);
  switch (command) 
  {
    case DRV_CMD_ECHO: 
        if (rlen < len) {
            *rbuf = (void *)driver_alloc(len);
        }
        (void)memcpy(*rbuf, buf, len);
        return (ErlDrvSSizeT)(len);
        break;
    case DRV_CMD_INIT:
        r = cmd_init(buf, len, &index, data, &x);
        break;
    case DRV_CMD_OPEN_CLIENT:
        r = cmd_open_client(buf, len, &index, data, &x);
        break;
    case DRV_CMD_SUBSCRIBE:
        r = cmd_subscribe(buf, len, &index, data, &x);
        break;
    case DRV_CMD_UNSUBSCRIBE:
        r = cmd_unsubscribe(buf, len, &index, data, &x);
        break;
    case DRV_CMD_PUBLISH:
        r = cmd_publish(buf, len, &index, data, &x);
        break;
    default:
        break;
  }

    // if (rlen < len) {
    //     *rbuf = (void *)driver_alloc(len);
    // }
    // (void)memcpy(*rbuf, buf, len);
    // return (ErlDrvSSizeT)(len);
exit_on_error:
  nlen = x.index;
	if (nlen > rlen) {
	    *rbuf =driver_alloc(nlen);
	}
	memcpy(*rbuf,x.buff,nlen);
	ei_x_free(&x);
  return nlen;
}

// static ErlDrvSSizeT call(ErlDrvData drv_data, unsigned int command, char *buf, ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen,
//                  unsigned int *flags)
// {
//     if (rlen < len) {
//         *rbuf = (void *)driver_alloc(len);
//     }
//     (void)memcpy(*rbuf, buf, len);
//     return (ErlDrvSSizeT)(len);
// }

static void handle_erl_msg(ErlDrvData handle, char *buff, 
                   ErlDrvSizeT bufflen)
{
  mosquitto_embed_data* d = (mosquitto_embed_data*)handle;

  // echo back
  driver_output(d->port, buff, bufflen);

  // EXTERN int erl_drv_output_term(ErlDrvTermData port,
	// 		       ErlDrvTermData* data,
	// 		       int len);
  // driver_output(d->port, "yes", 3);
}
static void on_write_block(struct mosquitto * mosq_context, mosq_sock_t sock, mosq_user_context_t context)
{
  mosquitto_embed_data *d = (mosquitto_embed_data*)context;
  DEBUG("on_write_block");
  driver_select(d->port, sock2event(sock), ERL_DRV_WRITE, 1);
}

static void on_socket_accept(struct mosquitto * mosq_context, mosq_sock_t sock, void* context)
{
  mosquitto_embed_data *d = (mosquitto_embed_data*)context;
  DEBUG("on_socket_accept");

  mosquitto__on_write_block(mosq_context, on_write_block, d);

  driver_select(d->port, sock2event(sock), ERL_DRV_READ, 1);
  driver_select(d->port, sock2event(sock), ERL_DRV_WRITE, 1);
}

static void handle_socket_input(ErlDrvData handle, ErlDrvEvent event)
{
  mosquitto_embed_data *d = (mosquitto_embed_data*)handle;
  // DEBUG("handle_socket_input");

  mosquitto__readsock(d->db,event2sock(event), on_socket_accept, d);
  
  mosquitto__loop_step(db);

  driver_set_timer(d->port, d->poll_period);
  // mosquitto__writesock(d->db,event2sock(event));
}

static void handle_socket_output(ErlDrvData handle, ErlDrvEvent event)
{
  mosquitto_embed_data *d = (mosquitto_embed_data*)handle;
  // DEBUG("handle_socket_output");

  // Disable socket notfications here as mosquitto__writesock() might need to enable them
  driver_select(d->port, sock2event(event), ERL_DRV_WRITE, 0);
}

/* Handling of timeout in driver */
static void timeout(ErlDrvData drv_data)
{
  mosquitto_embed_data *d = (mosquitto_embed_data*)drv_data;

  mosquitto__loop_step(db);

  driver_set_timer(d->port, d->poll_period);
}

static void process_exit(ErlDrvData handle, ErlDrvMonitor *monitor)
{
  
}

/* Called on behalf of driver_select when
  it is safe to release 'event'. A typical
  unix driver would call close(event) */
static void stop_select(ErlDrvEvent event, void* reserved)
{
    mosquitto__closesock(db, event2sock(event));
}

static int get_string(char *buf, ErlDrvSizeT len, int* index, char** s, ei_x_buff* x)
{
  
  char * new_string = NULL;
  int term_type = 0;
  int term_size = 0;
  
  if (ei_get_type(buf, index, &term_type, &term_size) < 0 || term_type != ERL_BINARY_EXT)
  {
      DEBUG("Expecting topic as Binary");
      encode_error(x);
      goto exit_on_error;
  }
  new_string = driver_alloc(term_size+1);

  long s_size;
  if (ei_decode_binary(buf, index, new_string, &s_size) < 0)
  {
      DEBUG("Cannot decode String");
      encode_error(x);
      goto exit_on_error;
  }
  new_string[term_size] = '\0';

  *s = new_string;  
  return 0;
exit_on_error:
  if(new_string != NULL)
  {
    driver_free(*s);
  }
  return -1;
}

static char* argc0 = "mosquitto";

static void args_to_argv(char * args,  int* argc, char*** argv)
{
  
  int count = 1;

  DEBUG("args_to_argv %s", args);

  if(args == NULL)
  {
    *argc=1;
    char **v = (char**)driver_alloc(sizeof(char *));
    v[0] = argc0;
    *argv = v;
    return;
  }

  for(int i =0; args[i] != '\0'; i++)
  {
    DEBUG("args_to_argv %d", i);
    if(args[i] == ' ')
    {
      count = count + 1;
    }
  }
  
  int size = count * sizeof(char *);
  char **v = (char**)driver_alloc(size);
  DEBUG("driver_alloc %d", size);

  // Note the args is already duplicated using get_s() so it is safe
  // here to chop the string up
  int j = 0;
  v[j] = argc0;
  j++;
  for(int i =0; args[i] != '\0'; i++)
  {
    if(i == 0)
    {
      v[j] = &args[i];
    }
    else if(args[i] == ' ')
    {
      args[i] = '\0';
      v[j++] = &args[i+1];
    }
  }

  *argc = count;
  *argv = v;
}

static void encode_ok(ei_x_buff* x)
{
    const char* k_ok = "ok";
    ei_x_encode_atom(x, k_ok);
}

static void encode_error(ei_x_buff* x)
{
    const char* k_error = "error";
    ei_x_encode_atom(x, k_error);
}

static ErlDrvBinary* ei_x_to_new_binary(ei_x_buff* x)
{
  ErlDrvBinary* bin = driver_alloc_binary(x->index);
  if (bin != NULL)
	  memcpy(&bin->orig_bytes[0], x->buff, x->index);
  return bin;
}

#define DRV_FLAGS (ERL_DRV_FLAG_USE_PORT_LOCKING | ERL_DRV_FLAG_SOFT_BUSY)

ErlDrvEntry mosquitto_embed_driver_entry = {
    NULL,                         /* F_PTR init, called when driver is loaded */
    start,                        /* L_PTR start, called when port is opened */
    stop,                         /* F_PTR stop, called when port is closed */
    handle_erl_msg,               /* F_PTR output, called when erlang has sent */
    handle_socket_input,          /* F_PTR ready_input, called when input descriptor ready */
    handle_socket_output,         /* F_PTR ready_output, called when output descriptor ready */
    "mosquitto_embed",            /* char *driver_name, the argument to open_port */
    NULL,                         /* F_PTR finish, called when unloaded */
    NULL,                         /* void *handle, Reserved by VM */
    NULL,                         /* F_PTR control, port_command callback */
    timeout,                      /* F_PTR timeout, Handling of timeout in driver */
    NULL,                         /* F_PTR outputv,  called when we have output from erlang
				                            to the port */
    NULL,                         /* F_PTR ready_async, only for async drivers */
    NULL,                         /* F_PTR flush, called when port is about 
                                    to be closed, but there is data in driver 
                                    queue */
    call,                         /* F_PTR call, much like control, sync call
                                     to driver */
    NULL,                         /* F_PTR event, called when an event selected 
                                     by driver_event() occurs. */
    ERL_DRV_EXTENDED_MARKER,      /* int extended marker, Should always be 
                                     set to indicate driver versioning */
    ERL_DRV_EXTENDED_MAJOR_VERSION, /* int major_version, should always be 
                                       set to this value */
    ERL_DRV_EXTENDED_MINOR_VERSION, /* int minor_version, should always be 
                                       set to this value */
    DRV_FLAGS,                      /* int driver_flags, see documentation */
    NULL,                           /* void *handle2, reserved for VM use */
    NULL,                           /* F_PTR process_exit, called when a 
                                       monitored process dies */
    stop_select                     /* F_PTR stop_select, called to close an 
                                       event object */
};

DRIVER_INIT(mosquitto_embed) /* must match name in driver_entry */
{
    return &mosquitto_embed_driver_entry;
}