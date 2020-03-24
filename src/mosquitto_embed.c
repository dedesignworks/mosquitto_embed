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

#include "erl_driver.h"

// #define BLE_PORT    "/dev/ttyS1"
// #define BLE_BAUD    B115200
// #define BLE_PARITY  0


//----------------------------------
// Defines must be in sync with .erl
//----------------------------------

typedef struct {
  ErlDrvPort  port;

} mosquitto_embed_data;


static ErlDrvData mosquitto_embed_start(ErlDrvPort port, char *buff)
{
  // char *portname = BLE_PORT;
  int fd = -1;
  struct termios tty;

  //----------------------------------
  // Create the Erlang Driver Ptr
  //----------------------------------
  mosquitto_embed_data* d = (mosquitto_embed_data*)driver_alloc(sizeof(mosquitto_embed_data));
  d->port = port;
  //----------------------------------
  // Open the Serial Port (TTY)
  //----------------------------------
  // if((fd = open (portname, O_RDWR | O_NOCTTY)) < 0) {
  //   goto exit_on_error;
  // }


  // d->serial_port = fd;

  // Set up to receive notifications when the serial_port is ready to be "read"
  //driver_select(d->port, (ErlDrvEvent)d->serial_port, ERL_DRV_READ,1);

  driver_output(d->port, "Started!", 9);

  return (ErlDrvData)d;

exit_on_error:
  //Try to gracefully cleanup
  driver_free(d);

  if (fd != -1)
  {
    close(fd);
  }
  return ERL_DRV_ERROR_GENERAL;
}

static void mosquitto_embed_stop(ErlDrvData handle)
{
  mosquitto_embed_data* d = (mosquitto_embed_data*)handle;
  // driver_select(d->port, (ErlDrvEvent)d->serial_port, ERL_DRV_READ, 0);
  driver_free((char*)handle);
}

static void mosquitto_embed_output(ErlDrvData handle, char *buff, 
                   ErlDrvSizeT bufflen)
{
  mosquitto_embed_data* d = (mosquitto_embed_data*)handle;
  // write(d->serial_port,buff,bufflen);
}


static void mosquitto_embed_ready_input(ErlDrvData handle, ErlDrvEvent event)
{
  // Note:  If we ever add a second port, we must test 
  // event == d->serial_port

  int bytes_read = 0;

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

ErlDrvEntry mosquitto_embed_driver_entry = {
    NULL,                         /* F_PTR init, called when driver is loaded */
    mosquitto_embed_start,        /* L_PTR start, called when port is opened */
    mosquitto_embed_stop,         /* F_PTR stop, called when port is closed */
    mosquitto_embed_output,       /* F_PTR output, called when erlang has sent */
    mosquitto_embed_ready_input,  /* F_PTR ready_input, called when input descriptor ready */
    NULL,                         /* F_PTR ready_output, called when output descriptor ready */
    "mosquitto_embed",            /* char *driver_name, the argument to open_port */
    NULL,                         /* F_PTR finish, called when unloaded */
    NULL,                         /* void *handle, Reserved by VM */
    NULL,                         /* F_PTR control, port_command callback */
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