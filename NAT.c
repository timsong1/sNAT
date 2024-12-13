#include <linux/kernel.h>
#include <linux/module.h>
 //#include <linux/netfilter.h>
 //#include <linux/netfilter_ipv4.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/time.h>
#include <net/tcp.h>
#define RWPERMISSION 0644
static __be32 myip;
static struct proc_dir_entry *NAT;
static struct proc_dir_entry *proc_ip, *proc_lan, *proc_timeout;

/*helper routines for IP address conversion*/
unsigned long ip_asc_to_int(char *strip) 
{
	unsigned long ip;
        unsigned int a[4];

        sscanf(strip, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]);
        ip = (a[0] << 24)+(a[1] << 16)+(a[2] << 8)+a[3] ;
	return ip;
}
void inet_ntoa(char *tmp, u_int32_t int_ip)
{

	sprintf(tmp, "%d.%d.%d.%d",  (int_ip) & 0xFF,	(int_ip >> 8 ) & 0xFF,(int_ip >> 16) & 0xFF,(int_ip >> 24) & 0xFF);
	return; 
}
static ssize_t proc_read_ip(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
	char tmp[16];
    inet_ntoa(tmp,myip);
    int len = sizeof(tmp);
    if(*offset >= len || copy_to_user(buffer,tmp,len)){
        pr_info("copy_to_user failed\n");
        return 0;
    }
    else{
        pr_info("proc_read_ip %s\n", file_pointer->f_path.dentry->d_name.name);
        *offset += len;
        return len;
    }
}
static ssize_t proc_write_ip(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{

}
static ssize_t proc_read_lan(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{

}
static ssize_t proc_write_lan(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{

}
static ssize_t proc_read_timeout(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{

}
static ssize_t proc_write_timeout(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{

}
static struct file_operations proc_ip_ops = {
    .read = &proc_read_ip,
    .write = &proc_write_ip,
};
static struct file_operations proc_lan_ops = {
    .read = &proc_read_lan,
    .write = &proc_write_lan,
};
static struct file_operations proc_timeout_ops = {
    .read = &proc_read_timeout,
    .write = &proc_write_timeout,
};

static int __init init(){
    int rv = 0;
    myip = htonl(ip_asc_to_int("192.168.2.10"));
    NAT = proc_mkdir("NAT", NULL); //set NULL will default to /proc
	if(NAT == NULL){
		rv = -ENOMEM;
		goto err;
	}
    proc_ip = proc_create("ip",RWPERMISSION,NULL,&proc_ip_ops);
    proc_lan = proc_create("lan",RWPERMISSION,NULL,&proc_lan_ops);
    proc_timeout = proc_create("timeout",RWPERMISSION,NULL,&proc_timeout_ops);

    return 0;
err:
    return rv;
}
static void __exit cleanup(void)
{

	remove_proc_entry("ip", NAT);
	remove_proc_entry("lan", NAT);
	remove_proc_entry("timeout", NAT);
	remove_proc_entry("knat", NULL);
	//nf_unregister_hook(&netfilter_ops_in);
	//nf_unregister_hook(&netfilter_ops_pre);

}

module_init(init);
module_exit(cleanup);

//MODULE_LICENSE("GPL");