//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define FAIL    -1

using namespace std;

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 
SSL_CTX* InitCTX(void)
{   const SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes,option;
    char *hostname, *portnum;
	 
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
 
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   
		ShowCerts(ssl);
		char msg[1024]={0};
		printf("\t\t\t********Secure ChatRoom********\n\n");
		printf("Please Enter your Username: ");
		gets(msg);
		SSL_write(ssl,msg,32);
		
		while(1)
		{ 	
			fflush(stdin);
			printf("\n\n\t\Option\t\t\tService\n\n");
			printf("\t  1. \t\t    Send a Message.\n\t  2. \t\t    Show New Messages\n\t  3. \t\t    Show Active Clients\n\n\n");
			printf("Select the service number: ");
			scanf(" %d",&option);
			fflush(stdout);
			msg[0]=option;
			SSL_write(ssl,msg,1);
			if(option==1)
			{
				int dest,sz;
				printf("Enter the Receiver-Id: ");
				scanf(" %d",&dest);
				printf("Enter the Message: ");
				fflush(stdout);
				gets(msg);		
				gets(msg);
				sz=strlen(msg);	
				SSL_write(ssl, &dest, sizeof(dest));   /* encrypt & send message */
				SSL_write(ssl, &sz, sizeof(sz));   
				SSL_write(ssl, msg, strlen(msg));
			}
			else if(option==2)
			{
				printf("\n\t\t\t*********New Messages**********\n\n");
				fflush(stdout);
				int sz, ptr=0;
				SSL_read(ssl,&sz,sizeof(sz));
		
				if(sz!=0)
				{
					sleep(1);
					SSL_read(ssl,msg,sz);
				}
	
				while(sz!=ptr)
				{
					int src=0,sz_in;
					memcpy(&src,msg+ptr,sizeof(src));
					ptr+=sizeof(src);
					memcpy(&sz_in,msg+ptr,sizeof(sz_in));
					ptr+=sizeof(sz_in);
					printf("Message from Client-Id %d: ",src);
					fwrite(msg+ptr,1,sz_in,stdout);
					printf("\n");
					ptr+=sz_in;
				}
			}
			else if(option==3)
			{
				int sz;
				SSL_read(ssl,&sz,sizeof(sz));
				//sleep(1);
				printf("\n\t\t\t*********List of Active Clients**********\n\n");
				printf("  \t\tUser-Name\t\t|\t\tClient-Id\n");
				printf("  \t\t_________\t\t \t\t_________\n\n");
				fflush(stdout);
				for(int i=0;i<sz;i++)
				{
					SSL_read(ssl,msg,36);
					printf("  \t\t  %s\t\t|\t\t     %d\n",msg,*((int *)(msg+32)));
					fflush(stdout);
				}
			}
			else
			{
				printf("Invalid Option\n");
			}
    		fflush(stdout);
		}
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
