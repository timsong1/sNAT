#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/time.h>
#include <net/tcp.h>

#define RWPERMISSION 0644 // rw- r-- r--
#define MAX_NAT_ENTRIES 65535
#define SET_ENTRY 133
#define PROCFS_MAX_SIZE 1024
struct nat_entry {
	__be32 lan_ipaddr;
	__be16 lan_port;
//	__be16 nat_port;
	unsigned long sec;	/*timestamp in seconds*/
	u_int8_t valid;
};
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;
static __be32 myip;
static __be32 lan_ip_mask;
static __be32 lan_ip_first;
/*the NAT table is indexed by the translated port i.e. source port after NAT for outgoing packet*/
static struct nat_entry nat_table[MAX_NAT_ENTRIES];
static int start = 0;
static int timeout = 60; //second
static char lanstr[20] = "10.0.2.15/24";
static u_int16_t port = 10000;
static struct proc_dir_entry *NAT;
static struct proc_dir_entry *proc_ip, *proc_lan, *proc_timeout, *proc_start;

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
    int len;
    len = sizeof(tmp);
    if(*offset >= len || copy_to_user(buffer,tmp,len)){
        pr_info("copy_to_user failed\n");
        return 0;
    }
    else{
        pr_info("proc_read_ip %s\n", file_pointer->f_path.dentry->d_name.name);
        pr_info("proc_read_ip tmp size : %d\n", sizeof(tmp));
        *offset += len;
        return len;
    }
}
static ssize_t proc_write_ip(
            struct file *file_pointer, 
            const char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    char tmp[16];
	if(buffer_length > 15)	
	{
		//don't try to convert that string.
		return -ENOSPC;
	}
    if(copy_from_user(tmp, buffer, buffer_length)){
		return -EFAULT;
	}
    *offset += buffer_length;
    tmp[buffer_length] = "\0";
    myip = htonl(ip_asc_to_int(tmp));
    return buffer_length;
}
static ssize_t proc_read_lan(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    int len,rv;
    char tmp[21];
    
    len = sprintf(tmp, "%s\n", lanstr);
    rv = len;
    if(*offset >= len || copy_to_user(buffer,tmp,len)){
        rv = 0;
    }
    else{
        *offset += len;
        pr_info("proc_read_lan %s\n", file_pointer->f_path.dentry->d_name.name);
    }
    return rv;
}
static ssize_t proc_write_lan(
            struct file *file_pointer, 
            const char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    return 0;
}
static ssize_t proc_read_timeout(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    int len,rv;
    char tmp[16];
    
    len = sprintf(tmp, "%u\n", timeout);
    rv = len;
    if(*offset >= len || copy_to_user(buffer,tmp,len)){
        rv = 0;
    }
    else{
        *offset += len;
        pr_info("proc_read_timeout %s\n", file_pointer->f_path.dentry->d_name.name);
    }
    return rv;
}
static ssize_t proc_write_timeout(
            struct file *file_pointer, 
            const char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    procfs_buffer_size = buffer_length;
	if(procfs_buffer_size >= PROCFS_MAX_SIZE){
        procfs_buffer_size = PROCFS_MAX_SIZE - 1;
	}
    if(copy_from_user(procfs_buffer, buffer, buffer_length)){
		return -EFAULT;
	}
    if(procfs_buffer[procfs_buffer_size-1] == '\n')
        procfs_buffer[procfs_buffer_size-1] = '\0';
    else
        procfs_buffer[procfs_buffer_size] = "\0";
    
    if (kstrtoint(procfs_buffer, 10, &timeout)) { 
        pr_info("Invalid input format:'%s'\n",procfs_buffer);
        return -EINVAL; 
    }
    *offset += procfs_buffer_size;
    return procfs_buffer_size;
}
static ssize_t proc_read_start(
            struct file *file_pointer, 
            char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    int len,rv;
    char tmp[16];
    
    len = sprintf(tmp, "%u\n", start);
    rv = len;
    if(*offset >= len || copy_to_user(buffer,tmp,len)){
        rv = 0;
    }
    else{
        *offset += len;
        pr_info("proc_read_start %s\n", file_pointer->f_path.dentry->d_name.name);
    }
    return rv;
}
static ssize_t proc_write_start(
            struct file *file_pointer, 
            const char __user *buffer,
            size_t buffer_length, 
            loff_t *offset)
{
    procfs_buffer_size = buffer_length;
	if(procfs_buffer_size >= PROCFS_MAX_SIZE){
        procfs_buffer_size = PROCFS_MAX_SIZE - 1;
	}
    if(copy_from_user(procfs_buffer, buffer, buffer_length)){
		return -EFAULT;
	}
    if(procfs_buffer[procfs_buffer_size-1] == '\n')
        procfs_buffer[procfs_buffer_size-1] = '\0';
    else
        procfs_buffer[procfs_buffer_size] = "\0";
    
    if (kstrtoint(procfs_buffer, 10, &start)) { 
        pr_info("Invalid input format:'%s'\n",procfs_buffer);
        return -EINVAL; 
    }
    *offset += procfs_buffer_size;
    return procfs_buffer_size;
}
static const struct proc_ops proc_ip_ops = {
    .proc_read = proc_read_ip,
    .proc_write = proc_write_ip,
};
static const struct proc_ops proc_lan_ops = {
    .proc_read = proc_read_lan,
    .proc_write = proc_write_lan,
};
static const struct proc_ops proc_timeout_ops = {
    .proc_read = proc_read_timeout,
    .proc_write = proc_write_timeout,
};
static const struct proc_ops proc_start_ops = {
    .proc_read = proc_read_start,
    .proc_write = proc_write_start,
};
static struct nf_hook_ops netfilter_ops_in, netfilter_ops_pre;
static struct net *net_ns;
/*find the nat table entry for given lan port. 
@sport = source port as obtained from packet from lan*/
__be16 find_nat_entry(__be32 saddr, __be16 sport)
{
	int i = 0;
	unsigned int t = 0;
	for(i = 0; i < MAX_NAT_ENTRIES; i++)
	{
		if((nat_table[i].lan_ipaddr == saddr) && (nat_table[i].lan_port == sport) && nat_table[i].valid)
		{
			t = (ktime_get_seconds() - nat_table[i].sec);
			if(t > timeout)
			{
				printk("NAT Entry timeout\n");
				nat_table[i].valid = 0;
				return 0;
			}	
			return i;
		}
	}
	return 0;
}
/* update the checksums for tcp and ip*/
void update_tcp_ip_checksum(
    struct sk_buff *skb, 
    struct tcphdr *tcph, 
	struct iphdr *iph)
{
		
	int len;
	if (!skb || !iph || !tcph) 
        return ;
	len = skb->len;
	
// update ip checksum
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
// update tcp checksum 
	tcph->check = 0;
	tcph->check = tcp_v4_check(
			len - 4*iph->ihl,
			iph->saddr, iph->daddr,
			csum_partial((char *)tcph, len-4*iph->ihl, 0));
	return;
	
}
// Source NAT
unsigned int main_hook_post(
        void *priv,
		struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be32 oldip, newip;
	__be16  newport;
	int len = 0;

    if(start == 0)
        return NF_ACCEPT;

    if(!skb)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    len = skb->len;
    if (!iph) 
        return NF_ACCEPT;

    if(iph->protocol == IPPROTO_TCP){
        oldip = iph->saddr;
		/*Is this packet from given LAN range*/
		if((oldip & lan_ip_mask) == lan_ip_first){

            tcph = (struct tcphdr*)((char *)iph + iph->ihl*4); // ihl : ip header length
			if(!tcph) return NF_ACCEPT;    
            			if(!tcph) return NF_ACCEPT;
			newport = find_nat_entry(iph->saddr, tcph->source);
			if(newport){
				/*NAT entry already exists*/
				tcph->source = newport;
			}
			else{
				/*Make a new NAT entry choose port numbers > 10000*/
				newport = htons(port++); 
				if(port == 0) 
                    port = 10000;
				nat_table[newport].valid = SET_ENTRY;
				nat_table[newport].lan_ipaddr = iph->saddr;
				nat_table[newport].lan_port = tcph->source;
				nat_table[newport].sec = ktime_get_seconds();
				tcph->source = newport;
				
			}
			iph->saddr = myip;	
			newip = iph->saddr;
			update_tcp_ip_checksum(skb, tcph, iph);	        
        }

    }
    return NF_ACCEPT;
}

// Destination NAT
unsigned int main_hook_pre(
        void *priv,
		struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be16 lan_port;
	
	if(start == 0)
		return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

	printk("PRE ROUTING");

	iph = ip_hdr(skb);

	if (!iph) return NF_ACCEPT;

	if (iph->protocol == IPPROTO_TCP){

		if(iph->daddr == myip){
			tcph = (struct tcphdr*)((char *)iph + iph->ihl*4);
			if(!tcph) return NF_ACCEPT;
			if(nat_table[tcph->dest].valid == SET_ENTRY){
                if(tcph->fin || tcph->rst){ // tcp connect finish
                    nat_table[tcph->dest].valid = 0;
                    return NF_ACCEPT;
                }
                else if(tcph->psh || tcph->ack){
                    // if active, entry will not expire
                    nat_table[tcph->dest].sec = ktime_get_seconds();
                }
                if((ktime_get_seconds() - nat_table[tcph->dest].sec) > timeout){
                    nat_table[tcph->dest].valid = 0;
                    return NF_DROP;
                }
				// translate ip addr and port
				lan_port = nat_table[tcph->dest].lan_port;
				iph->daddr = nat_table[tcph->dest].lan_ipaddr;
				tcph->dest = lan_port;
				//re-calculate checksum
				update_tcp_ip_checksum(skb, tcph, iph);
			}
		}
	}


	return NF_ACCEPT;

}


				// /*lazy checking of stale entries*/
				// if((get_seconds() - nat_table[tcph->dest].sec) > timeout)
				// {
				// 	/*stale entry which means we do not have a NAT entry for this packet*/
				// 	nat_table[tcph->dest].valid = 0;
				// 	return NF_ACCEPT;
				// }
static int __init init(void){
    
	int mask = 24;
	int i = 0, rv = 0;
	u_int32_t le_mask = 0;
	for(i = 0; i < mask; i++)
	{
		le_mask = le_mask << 1;
		le_mask = le_mask | 1;
	}
	//le_mask = le_mask << zeroes;
	lan_ip_mask = le_mask;
    lan_ip_first = htonl(ip_asc_to_int("10.0.2.0"));
    myip = htonl(ip_asc_to_int("122.42.13.59"));

    netfilter_ops_in.hook = main_hook_post;
	netfilter_ops_in.pf = PF_INET;
	netfilter_ops_in.hooknum = NF_INET_POST_ROUTING;
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;

	netfilter_ops_pre.hook = main_hook_pre;
	netfilter_ops_pre.pf = PF_INET;
	netfilter_ops_pre.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops_pre.priority = NF_IP_PRI_FIRST;

    NAT = proc_mkdir("NAT", NULL); //set NULL will default to /proc
	if(NAT == NULL){
		rv = -ENOMEM;
		goto err;
	}
    proc_ip = proc_create("ip",RWPERMISSION, NAT , &proc_ip_ops);
    proc_lan = proc_create("lan",RWPERMISSION, NAT , &proc_lan_ops);
    proc_timeout = proc_create("timeout",RWPERMISSION, NAT , &proc_timeout_ops);
    proc_start = proc_create("start",RWPERMISSION, NAT , &proc_start_ops);

    net_ns = &init_net;
    nf_register_net_hook(net_ns,&netfilter_ops_pre);
    nf_register_net_hook(net_ns,&netfilter_ops_in);

    return 0;
err:
    return rv;
}
static void __exit cleanup(void)
{

	remove_proc_entry("ip", NAT);
	remove_proc_entry("lan", NAT);
	remove_proc_entry("timeout", NAT);
	remove_proc_entry("NAT", NULL);
	nf_unregister_net_hook(net_ns,&netfilter_ops_in);
	nf_unregister_net_hook(net_ns,&netfilter_ops_pre);

}

module_init(init);
module_exit(cleanup);

MODULE_LICENSE("GPL");