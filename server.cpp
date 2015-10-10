//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <map>
#include <thread>
#include <mutex>
#include <vector>
 
#define FAIL    -1
 
using namespace std;

char inbuf[100][1024];
unsigned long inbuf_rptr[100]={0};
unsigned long inbuf_wptr[100]={0};
int client_id=-1;
map<unsigned long, int>m;

mutex mtx[100];
mutex online_mtx;
bool online[100];
int online_count=0;
char user_id[100][32];

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;
 
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
 
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
 
}
SSL_CTX* InitServerCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
void add(char *x, int sz, int dest, int src)
{

	char *dest_buf=inbuf[dest]+inbuf_wptr[dest];
	
	memcpy(dest_buf,&src,sizeof(src));
	memcpy(dest_buf+sizeof(src),&sz,sizeof(sz));
	memcpy(dest_buf+sizeof(src)+sizeof(sz),x,sz);

	inbuf_wptr[dest]+=sizeof(src)+sizeof(sz)+sz;

}

void Servlet(int client_id, SSL* ssl) /* Serve the connection -- threadable */
{   
	char buf[1024];
    int sd, bytes;
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        {
		ERR_print_errors_fp(stderr);
		}    
	else
    {
        ShowCerts(ssl);        /* get any certificates */
		SSL_read(ssl,buf,32);
		
		online_mtx.lock();
		memcpy(user_id[client_id],buf,32);
		online_count++;
		online[client_id]=true;
		
		online_mtx.unlock();		
		fflush(stdout);	
		while(1)
		{
        	bytes = SSL_read(ssl, buf, 1); /* get request */
        	if ( bytes > 0 )
        	{

			/* 1. Read Request */
			/* 2. Write Request  */

				if(buf[0]==1)
				{
					int dest,sz;
					SSL_read(ssl,&dest,sizeof(dest));
					SSL_read(ssl,&sz,sizeof(sz));
					SSL_read(ssl,buf,sz);

					mtx[dest].lock();
					add(buf,sz,dest,client_id);
					mtx[dest].unlock();
				}
				else if(buf[0]==2)
				{
					int sz;
					mtx[client_id].lock();
					sz=inbuf_wptr[client_id]-inbuf_rptr[client_id];
					SSL_write(ssl,&sz,sizeof(sz));
					if(sz)
					SSL_write(ssl,inbuf[client_id]+inbuf_rptr[client_id],sz);
					mtx[client_id].unlock();
					inbuf_rptr[client_id]+=sz;
				}
				else if(buf[0]==3)
				{
					char temp_send[3600];
					online_mtx.lock();					
					printf("List of size %d to be sent\n",online_count);
					int j=0;
					for(int i=0;i<100;i++)
					{
						if(online[i])
						{
							memcpy(temp_send+j*36,user_id[i],32);
							memcpy(temp_send+j*36+32,&i,sizeof(i));
							//printf("%d\n",i);							
							fflush(stdout);
							j++;
						}
					}
				
					
					SSL_write(ssl,&online_count,sizeof(online_count));
					SSL_write(ssl,temp_send,j*36);					
					online_mtx.unlock();
					
				}
			
				else
				{
					printf("Invalid Request\n");
					break;
				}
          
        	}
        	else
			{
            	ERR_print_errors_fp(stderr);
				break;
			}
		}
		printf("User %s is now Offline\n",user_id[client_id]);
		online[client_id]=false;
		online_count--;
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    char *portnum;
 
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
 
    portnum = strings[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
	printf("\t\t********Chatroom is up and running********\n\n");
    vector<thread> threads;
	    	
	
    while (1)
    {   
		struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
 
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
	
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

		client_id++;
		m[addr.sin_addr.s_addr]=client_id;

		threads.push_back(thread(Servlet,client_id,ssl));
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
