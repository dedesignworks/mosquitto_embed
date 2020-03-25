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

#define CMD_ECHO 0
#define CMD_INIT 1

static char* get_s(const char* buf, int len);
static void encode_ok(ei_x_buff* x);
static ErlDrvBinary* ei_x_to_new_binary(ei_x_buff* x);

//----------------------------------
// Defines must be in sync with .erl
//----------------------------------

typedef struct {
  ErlDrvPort  port;

} mosquitto_embed_data;


static ErlDrvData start(ErlDrvPort port, char *buff)
{
  // char *portname = BLE_PORT;
  // int fd = -1;

  //----------------------------------
  // Create the Erlang Driver Ptr
  //----------------------------------
  mosquitto_embed_data* d = (mosquitto_embed_data*)driver_alloc(sizeof(mosquitto_embed_data));
  d->port = port;
  set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
  //----------------------------------
  // Open the Serial Port (TTY)
  //----------------------------------
  // if((fd = open (portname, O_RDWR | O_NOCTTY)) < 0) {
  //   goto exit_on_error;
  // }


  // d->serial_port = fd;

  // Set up to receive notifications when the serial_port is ready to be "read"
  //driver_select(d->port, (ErlDrvEvent)d->serial_port, ERL_DRV_READ,1);

  return (ErlDrvData)d;

// exit_on_error:
//   //Try to gracefully cleanup
//   driver_free(d);

//   if (fd != -1)
//   {
//     close(fd);
//   }
//   return ERL_DRV_ERROR_GENERAL;
}

static void stop(ErlDrvData handle)
{
  // mosquitto_embed_data* d = (mosquitto_embed_data*)handle;
  // fprintf(stderr, "\nstop\n");
  // driver_select(d->port, (ErlDrvEvent)d->serial_port, ERL_DRV_READ, 0);
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

static void args_to_argv(char * args, char*** argv, int* argc)
{
  
  
  int count = 1;
  for(int i =0; args[i] != '\0'; i++)
  {
    if(args[i] == ' ')
    {
      count = count + 1;
    }
  }
  
  char **v = (char**)driver_alloc(count * sizeof(char *));

  // Note the args is already duplicated using get_s() so it is safe
  // here to chop the string up
  int j = 0;
  v[j] = &args[0];
  j++;
  for(int i =0; args[i] != '\0'; i++)
  {
    if(args[i] == ' ')
    {
      args[i] = '\0';
      v[j++] = &args[i+1];
    }
  }

  *argc = count;
  *argv = v;
}

static int cmd_init(char *args, mosquitto_embed_data* data, ei_x_buff* x)
{
  int argc;
  char **argv;

  args_to_argv(args, &argv, &argc);


  return 0;
}



static ErlDrvSSizeT control(ErlDrvData drv_data, unsigned int command, char *buf, 
                   ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen)
{
  int r;
  ei_x_buff x;
  mosquitto_embed_data* data = (mosquitto_embed_data*)drv_data;
  char* s;

  ei_x_new_with_version(&x);
  switch (command) {
    case CMD_ECHO: 
        s = get_s(buf, len);
        r = cmd_echo(s, data, &x);  
        driver_free(s);
        break;
      // case DRV_CONNECT:    r = do_connect(s, data, &x);  break;
      // case DRV_DISCONNECT: r = do_disconnect(data, &x);  break;
      // case DRV_SELECT:     r = do_select(s, data, &x);   break;
      default:             r = -1;        break;
  }
  *rbuf = (char*)ei_x_to_new_binary(&x);
  ei_x_free(&x);
  
  return r;
}

static void handle_erl_msg(ErlDrvData handle, char *buff, 
                   ErlDrvSizeT bufflen)
{
  mosquitto_embed_data* d = (mosquitto_embed_data*)handle;
  fprintf(stderr, "\noutput\n");

  // echo back
  driver_output(d->port, buff, bufflen);

  // EXTERN int erl_drv_output_term(ErlDrvTermData port,
	// 		       ErlDrvTermData* data,
	// 		       int len);



  // driver_output(d->port, "yes", 3);
}


static void handle_socket_input(ErlDrvData handle, ErlDrvEvent event)
{
  // Note:  If we ever add a second port, we must test 
  // event == d->serial_port

  // int bytes_read = 0;
  // fprintf(stderr, "\ninput\n");

  // mosquitto_embed_data* d;
  // char* read_buf;
  // int bytes_remain;
  // do 
  // {
  //   d = (mosquitto_embed_data*)handle;
  //   read_buf = (char*)&d->packet_in;
  //   bytes_remain = PKT_HEADER_SIZE;
  //   read_buf += d->rcv_bytes;

  //   // If we know how many bytes are left, then only try to read those
  //   if(d->rcv_bytes >= PKT_HEADER_SIZE) 
  //   {
  //     bytes_remain = pkt_size(&d->packet_in) - d->rcv_bytes;
  //   }

  //   bytes_read = read(d->serial_port,read_buf,bytes_remain);
  //   // fprintf(stderr,"Read %i bytes \r\n", bytes_read);
  //   d->rcv_bytes += bytes_read;
  //   if (d->rcv_bytes >= PKT_HEADER_SIZE)
  //   {
  //     // fprintf(stderr,"Header Received\r\n");
  //     // fprintf(stderr,"Packet Type %x \r\n", (char)d->packet_in.type);
  //     // fprintf(stderr,"Packet Size %i bytes \r\n", pkt_size(&d->packet_in));

  //     if (d->rcv_bytes >= pkt_size(&d->packet_in))
  //     {
  //       // We have the whole packet, Output it
  //       // fprintf(stderr,"Sending Packet %i bytes \r\n", pkt_size(&d->packet_in));
  //       driver_output(d->port, (char*)&d->packet_in, pkt_size(&d->packet_in));  
  //       d->rcv_bytes = 0;
  //     }
  //   }
  //   else
  //   {
  //     // We did not read enough to get the entire header.  We are done
  //     break;
  //   }
  //   // We only attempted to read a header or a single packet,
  //   // See if there is anything else remaining.
  // } while (bytes_read > 0);

}

static char* get_s(const char* buf, int len)
{
    char* result;
    if (len < 1 || len > 10000) return NULL;
    result = driver_alloc(len+1);
    memcpy(result, buf, len);
    result[len] = '\0';
    return result;
}

static void encode_ok(ei_x_buff* x)
{
    const char* k_ok = "ok";
    ei_x_encode_atom(x, k_ok);
}

static ErlDrvBinary* ei_x_to_new_binary(ei_x_buff* x)
{
  ErlDrvBinary* bin = driver_alloc_binary(x->index);
  if (bin != NULL)
	  memcpy(&bin->orig_bytes[0], x->buff, x->index);
  return bin;
}


ErlDrvEntry mosquitto_embed_driver_entry = {
    NULL,                         /* F_PTR init, called when driver is loaded */
    start,                        /* L_PTR start, called when port is opened */
    stop,                         /* F_PTR stop, called when port is closed */
    handle_erl_msg,               /* F_PTR output, called when erlang has sent */
    handle_socket_input,          /* F_PTR ready_input, called when input descriptor ready */
    NULL,                         /* F_PTR ready_output, called when output descriptor ready */
    "mosquitto_embed",            /* char *driver_name, the argument to open_port */
    NULL,                         /* F_PTR finish, called when unloaded */
    NULL,                         /* void *handle, Reserved by VM */
    control,                      /* F_PTR control, port_command callback */
    NULL,                         /* F_PTR timeout, reserved */
    NULL,                         /* F_PTR outputv, reserved */
    NULL,                         /* F_PTR ready_async, only for async drivers */
    NULL,                         /* F_PTR flush, called when port is about 
                                    to be closed, but there is data in driver 
                                    queue */
    NULL,                         /* F_PTR call, much like control, sync call
                                     to driver */
    NULL,                         /* F_PTR event, called when an event selected 
                                     by driver_event() occurs. */
    ERL_DRV_EXTENDED_MARKER,      /* int extended marker, Should always be 
                                     set to indicate driver versioning */
    ERL_DRV_EXTENDED_MAJOR_VERSION, /* int major_version, should always be 
                                       set to this value */
    ERL_DRV_EXTENDED_MINOR_VERSION, /* int minor_version, should always be 
                                       set to this value */
    0,                              /* int driver_flags, see documentation */
    NULL,                           /* void *handle2, reserved for VM use */
    NULL,                           /* F_PTR process_exit, called when a 
                                       monitored process dies */
    NULL                            /* F_PTR stop_select, called to close an 
                                       event object */
};

DRIVER_INIT(mosquitto_embed) /* must match name in driver_entry */
{
    return &mosquitto_embed_driver_entry;
}